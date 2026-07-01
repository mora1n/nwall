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
		"ip daddr @egress4 accept",
		"ct mark 0x6e77616c accept",
		"ct mark 0x6e776470 jump ingress_guarded",
		"ct mark != 0x6e776470 ct state established,related accept",
		"ct mark set 0x6e776470",
		"queue num 100",
		"timeout 10m",
		"set lease4 { type ipv4_addr; flags dynamic,timeout; }",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("渲染缺少 %q\n%s", must, out)
		}
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
