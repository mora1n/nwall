// Package nft 把配置渲染成 nftables 规则文本，并通过 nft 命令做 check/apply/回滚。
package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/dpi"
)

// TableName 是 nwall 使用的唯一 nftables 表名（inet 族同管 v4/v6）。
const TableName = "nwall"

// inputPriority 取足够靠前的负值，抢在 iptables-nft 兼容层(priority 0)之前，
// 保证 nwall 的 DROP 优先生效（见 README「诚实的限制」）。
const inputPriority = -200

// Input 是渲染所需的全部数据：配置 + 已展开的白名单来源前缀。
type Input struct {
	Cfg          conf.Config
	WLSrcV4      []netip.Prefix
	WLSrcV6      []netip.Prefix
	PortPolicies []PortPolicyInput
	EgressV4     []netip.Prefix
	EgressV6     []netip.Prefix
	LeaseRelayV4 []netip.Prefix
	LeaseRelayV6 []netip.Prefix
	LeaseTimeout string
	EnableDPI    bool
	NFQueueNum   int
}

// PortPolicyInput 是单个监听端口覆盖策略的渲染输入。
type PortPolicyInput struct {
	ListenPort int
	WLSrcV4    []netip.Prefix
	WLSrcV6    []netip.Prefix
}

// Render 把渲染输入转为完整的 `nft -f` 规则文本。
func Render(in Input) string {
	var b strings.Builder
	in.PortPolicies = sortedPortPolicyInputs(in.PortPolicies)
	b.WriteString("table inet " + TableName + " {\n")
	renderSets(&b, in)
	renderIngress(&b, in)
	renderForward(&b, in)
	renderEgress(&b, in)
	b.WriteString("}\n")
	return b.String()
}

func renderSets(b *strings.Builder, in Input) {
	cfg := in.Cfg
	fmt.Fprintf(b, "\tset open_ports { type inet_service; flags interval;%s }\n", elemsInline(portsToStrings(cfg.Protect.OpenPorts)))
	fmt.Fprintf(b, "\tset guarded_ports { type inet_service; flags interval;%s }\n", elemsInline(portsToStrings(cfg.Protect.GuardedPorts)))
	// 入站白名单来源集合（自定义 + CN geo 省/市，apply 时展开）。
	fmt.Fprintf(b, "\tset wl_src4 { type ipv4_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.WLSrcV4)))
	fmt.Fprintf(b, "\tset wl_src6 { type ipv6_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.WLSrcV6)))
	for _, policy := range in.PortPolicies {
		fmt.Fprintf(b, "\tset wl_src4_p%d { type ipv4_addr; flags interval; auto-merge;%s }\n", policy.ListenPort, elemsInline(prefixesToStrings(policy.WLSrcV4)))
		fmt.Fprintf(b, "\tset wl_src6_p%d { type ipv6_addr; flags interval; auto-merge;%s }\n", policy.ListenPort, elemsInline(prefixesToStrings(policy.WLSrcV6)))
	}
	if len(in.PortPolicies) > 0 {
		fmt.Fprintf(b, "\tmap port_policy { type inet_service : verdict;%s }\n", elemsInline(portPolicyVerdicts(in.PortPolicies, "wl_check_p")))
		fmt.Fprintf(b, "\tmap forward_port_policy { type inet_service : verdict;%s }\n", elemsInline(portPolicyVerdicts(in.PortPolicies, "forward_wl_check_p")))
	}
	fmt.Fprintf(b, "\tset skip_ports { type inet_service; flags interval;%s }\n", elemsInline(portsToStrings(cfg.Protect.ProtocolSkipPorts)))
	fmt.Fprintf(b, "\tset egress4 { type ipv4_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.EgressV4)))
	fmt.Fprintf(b, "\tset egress6 { type ipv6_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.EgressV6)))
	fmt.Fprintf(b, "\tset lease_relay4 { type ipv4_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.LeaseRelayV4)))
	fmt.Fprintf(b, "\tset lease_relay6 { type ipv6_addr; flags interval; auto-merge;%s }\n", elemsInline(prefixesToStrings(in.LeaseRelayV6)))
	// 租约动态集合（M3 写入，命中刷新 timeout）。nftables 当前不支持
	// interval+dynamic+timeout 组合，IPv4 前缀租约由服务端展开为主机元素。
	b.WriteString("\tset lease4 { type ipv4_addr; flags dynamic,timeout; }\n")
	b.WriteString("\tset lease6 { type ipv6_addr; flags dynamic,timeout; }\n")
}

func renderIngress(b *strings.Builder, in Input) {
	cfg := in.Cfg
	fmt.Fprintf(b, "\tchain ingress {\n")
	fmt.Fprintf(b, "\t\ttype filter hook input priority %d; policy drop;\n", inputPriority)
	// 安全垫：永远放行 loopback 与已建立连接，避免锁死。
	b.WriteString("\t\tiif \"lo\" accept\n")
	if in.EnableDPI {
		fmt.Fprintf(b, "\t\tct mark 0x%x accept\n", dpi.AcceptConnMark)
		fmt.Fprintf(b, "\t\tct mark 0x%x jump ingress_guarded\n", dpi.PendingConnMark)
		fmt.Fprintf(b, "\t\tct mark != 0x%x ct state established,related accept\n", dpi.PendingConnMark)
	} else {
		b.WriteString("\t\tct state established,related accept\n")
	}
	b.WriteString("\t\tct state invalid drop\n")
	renderLeaseRelayAccepts(b, cfg.Lease.ListenPort, in)
	// ① 公开端口（破窗保险，SSH 通常在此）。
	b.WriteString("\t\ttcp dport @open_ports accept\n")
	b.WriteString("\t\tudp dport @open_ports accept\n")
	// ② 受白名单保护：guard_all=true 时所有新入站；否则仅 guarded_ports。
	if cfg.Protect.GuardAll {
		b.WriteString("\t\tct state new jump ingress_guarded\n")
	} else {
		b.WriteString("\t\ttcp dport @guarded_ports ct state new jump ingress_guarded\n")
		b.WriteString("\t\tudp dport @guarded_ports ct state new jump ingress_guarded\n")
	}
	// ③ 其余落 policy drop 兜底（隐身）。
	b.WriteString("\t}\n")

	// 受保护流量判定链：租约命中即续期，再查白名单；命中后才进入 DPI。
	b.WriteString("\tchain ingress_guarded {\n")
	leaseTimeout := strings.TrimSpace(in.LeaseTimeout)
	if leaseTimeout == "" {
		leaseTimeout = "3d"
	}
	fmt.Fprintf(b, "\t\tip saddr @lease4 update @lease4 { ip saddr timeout %s } jump ingress_allowed\n", leaseTimeout)
	fmt.Fprintf(b, "\t\tip6 saddr @lease6 update @lease6 { ip6 saddr timeout %s } jump ingress_allowed\n", leaseTimeout)
	if len(in.PortPolicies) > 0 {
		b.WriteString("\t\ttcp dport vmap @port_policy\n")
		b.WriteString("\t\tudp dport vmap @port_policy\n")
	}
	if cfg.Ingress.Enabled {
		b.WriteString("\t\tjump wl_check\n")
	} else {
		b.WriteString("\t\tjump ingress_allowed\n")
	}
	b.WriteString("\t}\n")

	for _, policy := range in.PortPolicies {
		fmt.Fprintf(b, "\tchain wl_check_p%d {\n", policy.ListenPort)
		fmt.Fprintf(b, "\t\tip saddr @wl_src4_p%d jump ingress_allowed\n", policy.ListenPort)
		fmt.Fprintf(b, "\t\tip6 saddr @wl_src6_p%d jump ingress_allowed\n", policy.ListenPort)
		b.WriteString("\t\tdrop\n")
		b.WriteString("\t}\n")
	}

	// 白名单判定链（M2 起 wl_src* 有元素时生效；未命中即 drop）。
	b.WriteString("\tchain wl_check {\n")
	b.WriteString("\t\tip saddr @wl_src4 jump ingress_allowed\n")
	b.WriteString("\t\tip6 saddr @wl_src6 jump ingress_allowed\n")
	b.WriteString("\t\tdrop\n")
	b.WriteString("\t}\n")

	renderAllowedChain(b, "ingress_allowed", "\t\ttcp dport @skip_ports accept\n\t\tudp dport @skip_ports accept\n", in)
}

func renderLeaseRelayAccepts(b *strings.Builder, port int, in Input) {
	if port <= 0 || port > 65535 {
		return
	}
	if len(in.LeaseRelayV4) > 0 {
		fmt.Fprintf(b, "\t\tip saddr @lease_relay4 tcp dport %d accept\n", port)
	}
	if len(in.LeaseRelayV6) > 0 {
		fmt.Fprintf(b, "\t\tip6 saddr @lease_relay6 tcp dport %d accept\n", port)
	}
}

func renderForward(b *strings.Builder, in Input) {
	cfg := in.Cfg
	fmt.Fprintf(b, "\tchain forward {\n")
	fmt.Fprintf(b, "\t\ttype filter hook forward priority %d; policy accept;\n", inputPriority)
	if in.EnableDPI {
		fmt.Fprintf(b, "\t\tct status dnat ct mark 0x%x accept\n", dpi.AcceptConnMark)
		fmt.Fprintf(b, "\t\tct status dnat ct mark 0x%x jump forward_guarded\n", dpi.PendingConnMark)
		b.WriteString("\t\tct status dnat ct state established,related accept\n")
	} else {
		b.WriteString("\t\tct status dnat ct state established,related accept\n")
	}
	b.WriteString("\t\tct status dnat ct state invalid drop\n")
	b.WriteString("\t\tct status dnat meta l4proto tcp ct original proto-dst @open_ports accept\n")
	b.WriteString("\t\tct status dnat meta l4proto udp ct original proto-dst @open_ports accept\n")
	if cfg.Protect.GuardAll {
		b.WriteString("\t\tct status dnat ct state new jump forward_guarded\n")
	} else {
		b.WriteString("\t\tct status dnat ct state new meta l4proto tcp ct original proto-dst @guarded_ports jump forward_guarded\n")
		b.WriteString("\t\tct status dnat ct state new meta l4proto udp ct original proto-dst @guarded_ports jump forward_guarded\n")
	}
	b.WriteString("\t\tct status dnat ct state new drop\n")
	b.WriteString("\t}\n")

	leaseTimeout := strings.TrimSpace(in.LeaseTimeout)
	if leaseTimeout == "" {
		leaseTimeout = "3d"
	}
	b.WriteString("\tchain forward_guarded {\n")
	fmt.Fprintf(b, "\t\tip saddr @lease4 update @lease4 { ip saddr timeout %s } jump forward_allowed\n", leaseTimeout)
	fmt.Fprintf(b, "\t\tip6 saddr @lease6 update @lease6 { ip6 saddr timeout %s } jump forward_allowed\n", leaseTimeout)
	if len(in.PortPolicies) > 0 {
		b.WriteString("\t\tmeta l4proto tcp ct original proto-dst vmap @forward_port_policy\n")
		b.WriteString("\t\tmeta l4proto udp ct original proto-dst vmap @forward_port_policy\n")
	}
	if cfg.Ingress.Enabled {
		b.WriteString("\t\tjump forward_wl_check\n")
	} else {
		b.WriteString("\t\tjump forward_allowed\n")
	}
	b.WriteString("\t}\n")

	for _, policy := range in.PortPolicies {
		fmt.Fprintf(b, "\tchain forward_wl_check_p%d {\n", policy.ListenPort)
		fmt.Fprintf(b, "\t\tip saddr @wl_src4_p%d jump forward_allowed\n", policy.ListenPort)
		fmt.Fprintf(b, "\t\tip6 saddr @wl_src6_p%d jump forward_allowed\n", policy.ListenPort)
		b.WriteString("\t\tdrop\n")
		b.WriteString("\t}\n")
	}

	b.WriteString("\tchain forward_wl_check {\n")
	b.WriteString("\t\tip saddr @wl_src4 jump forward_allowed\n")
	b.WriteString("\t\tip6 saddr @wl_src6 jump forward_allowed\n")
	b.WriteString("\t\tdrop\n")
	b.WriteString("\t}\n")

	renderAllowedChain(b, "forward_allowed", "\t\tmeta l4proto tcp ct original proto-dst @skip_ports accept\n\t\tmeta l4proto udp ct original proto-dst @skip_ports accept\n", in)
}

func renderAllowedChain(b *strings.Builder, name, skipRules string, in Input) {
	b.WriteString("\tchain " + name + " {\n")
	b.WriteString(skipRules)
	if in.EnableDPI {
		queue := in.NFQueueNum
		if queue <= 0 {
			queue = 100
		}
		fmt.Fprintf(b, "\t\tct mark set 0x%x\n", dpi.PendingConnMark)
		fmt.Fprintf(b, "\t\tqueue num %d\n", queue)
	} else {
		b.WriteString("\t\taccept\n")
	}
	b.WriteString("\t}\n")
}

func renderEgress(b *strings.Builder, in Input) {
	if !in.Cfg.Egress.Enabled {
		return
	}
	b.WriteString("\tchain egress {\n")
	b.WriteString("\t\ttype filter hook output priority -200; policy drop;\n")
	b.WriteString("\t\toif \"lo\" accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")
	b.WriteString("\t\tip daddr @egress4 accept\n")
	b.WriteString("\t\tip6 daddr @egress6 accept\n")
	b.WriteString("\t}\n")
}

func portsToStrings(ports []int) []string {
	nums := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		nums = append(nums, p)
	}
	sort.Ints(nums)
	if len(nums) == 0 {
		return nil
	}
	out := make([]string, 0, len(nums))
	start := nums[0]
	prev := nums[0]
	for _, p := range nums[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		out = append(out, formatPortInterval(start, prev))
		start = p
		prev = p
	}
	return append(out, formatPortInterval(start, prev))
}

func formatPortInterval(start, end int) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func portPolicyVerdicts(policies []PortPolicyInput, chainPrefix string) []string {
	out := make([]string, 0, len(policies))
	for _, policy := range policies {
		out = append(out, fmt.Sprintf("%d : jump %s%d", policy.ListenPort, chainPrefix, policy.ListenPort))
	}
	return out
}

// elemsInline 渲染集合的内联初始元素：` elements = { a, b }`，空集返回空串。
func elemsInline(elems []string) string {
	if len(elems) == 0 {
		return ""
	}
	return " elements = { " + strings.Join(elems, ", ") + " }"
}

// prefixesToStrings 把前缀去重并排序为字符串（供 nft 元素渲染，确定性输出）。
func prefixesToStrings(prefixes []netip.Prefix) []string {
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		s := p.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortedPortPolicyInputs(in []PortPolicyInput) []PortPolicyInput {
	out := append([]PortPolicyInput(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ListenPort < out[j].ListenPort
	})
	return out
}
