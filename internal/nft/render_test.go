package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/mora1n/nwall/internal/conf"
)

// 安全垫必须在任何配置下都存在，这是「不锁死自己」的核心保证。
func TestRenderAlwaysHasSafetyNet(t *testing.T) {
	for _, name := range []string{"default", "guard_all", "selective"} {
		cfg := conf.Default()
		switch name {
		case "guard_all":
			cfg.Protect.GuardAll = true
		case "selective":
			cfg.Protect.GuardAll = false
			cfg.Protect.GuardedPorts = []int{8443}
		}
		out := Render(Input{Cfg: cfg})
		for _, must := range []string{
			"iif \"lo\" accept",
			"ct state established,related accept",
			"tcp dport @open_ports accept",
			"type filter hook forward priority -200; policy accept;",
			"ct status dnat ct state established,related accept",
			"policy drop;",
		} {
			if !strings.Contains(out, must) {
				t.Errorf("[%s] 渲染缺少安全垫片段 %q\n%s", name, must, out)
			}
		}
	}
}

func TestRenderGuardAllTogglesDispatch(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.GuardAll = true
	got := Render(Input{Cfg: cfg})
	for _, must := range []string{
		"ct state new jump ingress_guarded",
		"ct status dnat ct state new jump forward_guarded",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("guard_all=true 应对所有新入站和 DNAT 转发分流，缺少 %q\n%s", must, got)
		}
	}
	cfg.Protect.GuardAll = false
	got = Render(Input{Cfg: cfg})
	for _, must := range []string{
		"tcp dport @guarded_ports ct state new jump ingress_guarded",
		"ct status dnat ct state new meta l4proto tcp ct original proto-dst @guarded_ports jump forward_guarded",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("guard_all=false 应仅对 guarded_ports 分流，缺少 %q\n%s", must, got)
		}
	}
}

func TestRenderOpenPortsElements(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.OpenPorts = []int{22, 443, 22} // 含重复，应去重
	out := Render(Input{Cfg: cfg})
	if !strings.Contains(out, "set open_ports") {
		t.Fatalf("缺少 open_ports 集合定义\n%s", out)
	}
	if !strings.Contains(out, "elements = { 22, 443 }") {
		t.Errorf("open_ports 元素渲染不符（应去重+有序）\n%s", out)
	}
}

func TestRenderOpenPort40422IsAccepted(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.OpenPorts = []int{40422}
	out := Render(Input{Cfg: cfg})
	for _, must := range []string{
		"elements = { 40422 }",
		"tcp dport @open_ports accept",
		"udp dport @open_ports accept",
		"ct status dnat meta l4proto tcp ct original proto-dst @open_ports accept",
		"ct status dnat meta l4proto udp ct original proto-dst @open_ports accept",
		"ct status dnat ct state new drop",
	} {
		if !strings.Contains(out, must) {
			t.Fatalf("40422 公开端口渲染缺少 %q\n%s", must, out)
		}
	}
}

func TestRenderLeaseRelayCanReachAgentPort(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.GuardAll = true
	cfg.Ingress.Enabled = true
	cfg.Lease.ListenPort = 41888
	out := Render(Input{
		Cfg:          cfg,
		LeaseRelayV4: []netip.Prefix{netip.MustParsePrefix("198.176.52.125/32")},
		LeaseRelayV6: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
	})
	for _, must := range []string{
		"set lease_relay4 { type ipv4_addr; flags interval; auto-merge; elements = { 198.176.52.125/32 } }",
		"set lease_relay6 { type ipv6_addr; flags interval; auto-merge; elements = { 2001:db8::1/128 } }",
		"ip saddr @lease_relay4 tcp dport 41888 accept",
		"ip6 saddr @lease_relay6 tcp dport 41888 accept",
	} {
		if !strings.Contains(out, must) {
			t.Fatalf("lease relay 应能访问 TCP 租约 agent，缺少 %q\n%s", must, out)
		}
	}
	if strings.Contains(out, "udp dport 41888") {
		t.Fatalf("TCP 租约 agent 不应放行 UDP\n%s", out)
	}
}

func TestRenderForwardUsesOriginalPublicPort(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.OpenPorts = []int{40422}
	cfg.Protect.GuardAll = false
	cfg.Protect.GuardedPorts = []int{41423}
	out := Render(Input{Cfg: cfg})
	for _, must := range []string{
		"set open_ports { type inet_service; flags interval; elements = { 40422 } }",
		"set guarded_ports { type inet_service; flags interval; elements = { 41423 } }",
		"ct status dnat meta l4proto tcp ct original proto-dst @open_ports accept",
		"ct status dnat ct state new meta l4proto tcp ct original proto-dst @guarded_ports jump forward_guarded",
	} {
		if !strings.Contains(out, must) {
			t.Fatalf("DNAT forward 应按公网原始端口判定，缺少 %q\n%s", must, out)
		}
	}
}

func TestRenderPortIntervals(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.OpenPorts = []int{40000, 40001, 40002, 50000}
	out := Render(Input{Cfg: cfg})
	if !strings.Contains(out, "elements = { 40000-40002, 50000 }") {
		t.Errorf("open_ports 应压缩连续区间\n%s", out)
	}
}

func TestRenderSingleTable(t *testing.T) {
	out := Render(Input{Cfg: conf.Default()})
	if strings.Count(out, "table inet "+TableName) != 1 {
		t.Errorf("应只渲染单一 inet %s 表\n%s", TableName, out)
	}
}

func TestRenderPortPolicyOverride(t *testing.T) {
	cfg := conf.Default()
	cfg.Ingress.Enabled = true
	out := Render(Input{
		Cfg: cfg,
		PortPolicies: []PortPolicyInput{{
			ListenPort: 8443,
			WLSrcV4:    []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			WLSrcV6:    []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		}},
	})
	for _, must := range []string{
		"set wl_src4_p8443",
		"set wl_src6_p8443",
		"map port_policy",
		"map forward_port_policy",
		"8443 : jump wl_check_p8443",
		"8443 : jump forward_wl_check_p8443",
		"tcp dport vmap @port_policy",
		"udp dport vmap @port_policy",
		"meta l4proto tcp ct original proto-dst vmap @forward_port_policy",
		"meta l4proto udp ct original proto-dst vmap @forward_port_policy",
		"chain wl_check_p8443",
		"chain forward_wl_check_p8443",
		"ip saddr @wl_src4_p8443 jump ingress_allowed",
		"ip6 saddr @wl_src6_p8443 jump ingress_allowed",
		"ip saddr @wl_src4_p8443 jump forward_allowed",
		"ip6 saddr @wl_src6_p8443 jump forward_allowed",
		"\t\tdrop\n",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("端口覆盖渲染缺少 %q\n%s", must, out)
		}
	}
}

func TestRenderIngressPriorityOrder(t *testing.T) {
	cfg := conf.Default()
	cfg.Ingress.Enabled = true
	cfg.Lease.ListenPort = 41888
	out := Render(Input{
		Cfg:          cfg,
		LeaseRelayV4: []netip.Prefix{netip.MustParsePrefix("198.176.52.125/32")},
		PortPolicies: []PortPolicyInput{{
			ListenPort: 8443,
			WLSrcV4:    []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}},
	})
	ingress := between(t, out, "\tchain ingress {\n", "\t}\n")
	assertBefore(t, ingress, "ip saddr @lease_relay4 tcp dport 41888 accept", "tcp dport @open_ports accept")
	assertBefore(t, ingress, "tcp dport @open_ports accept", "ct state invalid drop")
	assertBefore(t, ingress, "ct state invalid drop", "ct state new jump ingress_guarded")

	guarded := between(t, out, "\tchain ingress_guarded {\n", "\t}\n")
	assertBefore(t, guarded, "ip saddr & 255.255.255.0 == @lease4_24 update @lease4_24", "tcp dport vmap @port_policy")
	assertBefore(t, guarded, "tcp dport vmap @port_policy", "jump wl_check")
}

func TestRenderForwardPriorityOrder(t *testing.T) {
	cfg := conf.Default()
	cfg.Ingress.Enabled = true
	out := Render(Input{
		Cfg: cfg,
		PortPolicies: []PortPolicyInput{{
			ListenPort: 41423,
			WLSrcV4:    []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}},
	})
	forward := between(t, out, "\tchain forward {\n", "\t}\n")
	assertBefore(t, forward, "ct status dnat meta l4proto tcp ct original proto-dst @open_ports accept", "ct status dnat ct state invalid drop")
	assertBefore(t, forward, "ct status dnat ct state invalid drop", "ct status dnat ct state new jump forward_guarded")

	guarded := between(t, out, "\tchain forward_guarded {\n", "\t}\n")
	assertBefore(t, guarded, "ip saddr & 255.255.255.0 == @lease4_24 update @lease4_24", "meta l4proto tcp ct original proto-dst vmap @forward_port_policy")
	assertBefore(t, guarded, "meta l4proto tcp ct original proto-dst vmap @forward_port_policy", "jump forward_wl_check")
}

func TestRenderEgressAndDPI(t *testing.T) {
	cfg := conf.Default()
	cfg.Ingress.Enabled = true
	cfg.Egress.Enabled = true
	cfg.Protect.BlockHTTP = true
	cfg.Protect.ProtocolSkipPorts = []int{22, 8443}
	out := Render(Input{
		Cfg:          cfg,
		EgressV4:     []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		EgressV6:     []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
		EnableDPI:    true,
		NFQueueNum:   100,
		LeaseTimeout: "10m",
	})
	for _, must := range []string{
		"set skip_ports { type inet_service; flags interval; elements = { 22, 8443 } }",
		"set egress4",
		"198.51.100.0/24",
		"chain egress",
		"type filter hook output priority -200; policy drop;",
		"tcp sport @open_ports accept",
		"udp sport @open_ports accept",
		"tcp sport @guarded_ports accept",
		"udp sport @guarded_ports accept",
		"ip daddr @egress4 accept",
		"ct mark 0x6e77616c accept",
		"ct mark 0x6e776470 jump ingress_guarded",
		"ct mark != 0x6e776470 ct state established,related accept",
		"ct mark set 0x6e776470",
		"queue num 100",
		"timeout 10m",
		"set lease4_24 { type ipv4_addr; flags dynamic,timeout; }",
		"set lease4_32 { type ipv4_addr; flags dynamic,timeout; }",
		"ip saddr & 255.255.255.0 == @lease4_24 update @lease4_24 { ip saddr & 255.255.255.0 timeout 10m }",
		"ip saddr @lease4_32 update @lease4_32 { ip saddr timeout 10m }",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("渲染缺少 %q\n%s", must, out)
		}
	}
	if strings.Contains(out, "set lease4 {") {
		t.Errorf("IPv4 lease 不应使用旧 host-only lease4 set\n%s", out)
	}
	if strings.Contains(out, "flags interval,dynamic,timeout") {
		t.Errorf("nftables 不支持 interval,dynamic,timeout 组合\n%s", out)
	}
	ingress := between(t, out, "\tchain ingress {\n", "\t}\n")
	if strings.Contains(ingress, "\t\tct state established,related accept\n") {
		t.Errorf("DPI 开启时不应无条件放行 established，否则会绕过首个应用层 payload\n%s", out)
	}
	wlCheck := between(t, out, "\tchain wl_check {\n", "\t}\n")
	if strings.Contains(wlCheck, "queue num") {
		t.Errorf("白名单未命中时不应进入 DPI queue\n%s", out)
	}
	if !strings.Contains(wlCheck, "\t\tdrop\n") {
		t.Errorf("白名单未命中应直接 drop\n%s", out)
	}
	egress := between(t, out, "\tchain egress {\n", "\t}\n")
	assertBefore(t, egress, "ct state established,related accept", "tcp sport @open_ports accept")
	assertBefore(t, egress, "udp sport @guarded_ports accept", "ip daddr @egress4 accept")
	assertBefore(t, egress, "udp sport @guarded_ports accept", "ip6 daddr @egress6 accept")
	assertBefore(t, egress, "ip daddr @egress4 accept", "ct state invalid drop")
	assertBefore(t, egress, "ip6 daddr @egress6 accept", "ct state invalid drop")
}

func TestRenderDPIWorksWhenIngressWhitelistDisabled(t *testing.T) {
	cfg := conf.Default()
	cfg.Protect.BlockHTTP = true
	out := Render(Input{
		Cfg:       cfg,
		EnableDPI: true,
	})

	ingressGuarded := between(t, out, "\tchain ingress_guarded {\n", "\t}\n")
	for _, must := range []string{
		"\t\tjump ingress_allowed\n",
		"timeout 3d",
	} {
		if !strings.Contains(ingressGuarded, must) {
			t.Fatalf("白名单关闭时 ingress_guarded 应进入 allowed/DPI，缺少 %q\n%s", must, out)
		}
	}
	if strings.Contains(ingressGuarded, "jump wl_check") {
		t.Fatalf("白名单关闭时 ingress_guarded 不应进入空白名单链\n%s", out)
	}

	forwardGuarded := between(t, out, "\tchain forward_guarded {\n", "\t}\n")
	if !strings.Contains(forwardGuarded, "\t\tjump forward_allowed\n") {
		t.Fatalf("白名单关闭时 forward_guarded 应进入 allowed/DPI\n%s", out)
	}
	if strings.Contains(forwardGuarded, "jump forward_wl_check") {
		t.Fatalf("白名单关闭时 forward_guarded 不应进入空白名单链\n%s", out)
	}

	ingressAllowed := between(t, out, "\tchain ingress_allowed {\n", "\t}\n")
	forwardAllowed := between(t, out, "\tchain forward_allowed {\n", "\t}\n")
	for _, chain := range []string{ingressAllowed, forwardAllowed} {
		if !strings.Contains(chain, "ct mark set 0x6e776470") || !strings.Contains(chain, "queue num 100") {
			t.Fatalf("白名单关闭且 DPI 开启时 allowed 链应进入 NFQUEUE\n%s", out)
		}
	}
}

func TestRenderLeaseTimeoutDefaultsTo3d(t *testing.T) {
	out := Render(Input{Cfg: conf.Default()})
	if !strings.Contains(out, "timeout 3d") {
		t.Fatalf("租约 timeout 默认应为 3d\n%s", out)
	}
}

func between(t *testing.T, text, start, end string) string {
	t.Helper()
	i := strings.Index(text, start)
	if i < 0 {
		t.Fatalf("missing start %q in\n%s", start, text)
	}
	rest := text[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("missing end %q in\n%s", end, rest)
	}
	return rest[:j]
}

func assertBefore(t *testing.T, text, first, second string) {
	t.Helper()
	i := strings.Index(text, first)
	j := strings.Index(text, second)
	if i < 0 || j < 0 {
		t.Fatalf("missing priority fragments %q or %q in\n%s", first, second, text)
	}
	if i >= j {
		t.Fatalf("expected %q before %q in\n%s", first, second, text)
	}
}
