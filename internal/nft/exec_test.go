package nft

import (
	"net/netip"
	"testing"
)

func TestLeaseElementValueUsesHostAddress(t *testing.T) {
	got, err := leaseElementRule(netip.MustParsePrefix("127.0.0.1/32"), "10m")
	if err != nil {
		t.Fatalf("leaseElementRule: %v", err)
	}
	want := "add element inet nwall lease4 { 127.0.0.1 timeout 10m }\n"
	if got != want {
		t.Fatalf("rule mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestLeaseElementRejectsNetworkPrefix(t *testing.T) {
	if _, err := leaseElementRule(netip.MustParsePrefix("203.0.113.0/24"), "10m"); err == nil {
		t.Fatal("dynamic timeout lease set 不支持网络前缀元素")
	}
}

func TestLeasePrefixRuleExpandsIPv4Prefix(t *testing.T) {
	got, err := leasePrefixRule(netip.MustParsePrefix("203.0.113.8/30"), "10m")
	if err != nil {
		t.Fatalf("leasePrefixRule: %v", err)
	}
	want := "add element inet nwall lease4 { 203.0.113.8 timeout 10m, 203.0.113.9 timeout 10m, 203.0.113.10 timeout 10m, 203.0.113.11 timeout 10m }\n"
	if got != want {
		t.Fatalf("rule mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestLeasePrefixRuleRejectsLargeIPv4Prefix(t *testing.T) {
	if _, err := leasePrefixRule(netip.MustParsePrefix("203.0.112.0/23"), "10m"); err == nil {
		t.Fatal("IPv4 /23 应拒绝")
	}
}
