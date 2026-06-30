package egress

import "testing"

func TestParseOnlinkCIDRs(t *testing.T) {
	got := parseOnlinkCIDRs(`2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0
3: lo    inet 127.0.0.1/8 scope global lo
4: eth0    inet6 2001:db8::1/64 scope global`)
	if len(got) != 2 {
		t.Fatalf("onlink 数量不符: %v", got)
	}
	if got[0].String() != "192.0.2.0/24" || got[1].String() != "2001:db8::/64" {
		t.Fatalf("onlink 解析不符: %v", got)
	}
}

func TestParseGatewayCIDRs(t *testing.T) {
	got := parseGatewayCIDRs(`default via 192.0.2.1 dev eth0
default via fe80::1 dev eth0`)
	if len(got) != 2 {
		t.Fatalf("gateway 数量不符: %v", got)
	}
	if got[0].String() != "192.0.2.1/32" || got[1].String() != "fe80::1/128" {
		t.Fatalf("gateway 解析不符: %v", got)
	}
}
