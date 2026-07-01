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
	if got := Render(Input{Cfg: cfg}); !strings.Contains(got, "ct state new jump ingress_guarded") {
		t.Errorf("guard_all=true 应对所有新入站分流\n%s", got)
	}
	cfg.Protect.GuardAll = false
	if got := Render(Input{Cfg: cfg}); !strings.Contains(got, "tcp dport @guarded_ports ct state new jump ingress_guarded") {
		t.Errorf("guard_all=false 应仅对 guarded_ports 分流\n%s", got)
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
	out := Render(Input{
		Cfg: conf.Default(),
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
		"8443 : jump wl_check_p8443",
		"tcp dport vmap @port_policy",
		"udp dport vmap @port_policy",
		"chain wl_check_p8443",
		"ip saddr @wl_src4_p8443 accept",
		"ip6 saddr @wl_src6_p8443 accept",
		"\t\tdrop\n",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("端口覆盖渲染缺少 %q\n%s", must, out)
		}
	}
}

func TestRenderEgressAndDPI(t *testing.T) {
	cfg := conf.Default()
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
		"ct mark != 0x6e776470 ct state established,related accept",
		"ct mark 0x6e776470 jump ingress_guarded",
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
