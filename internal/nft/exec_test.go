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
	want := "add element inet nwall lease4_32 { 127.0.0.1 timeout 10m }\n"
	if got != want {
		t.Fatalf("rule mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestLeaseElementRejectsNetworkPrefix(t *testing.T) {
	if _, err := leaseElementRule(netip.MustParsePrefix("203.0.113.0/24"), "10m"); err == nil {
		t.Fatal("dynamic timeout lease set 不支持网络前缀元素")
	}
}

func TestLeasePrefixRuleStoresIPv4NetworkKey(t *testing.T) {
	got, err := leasePrefixRule(netip.MustParsePrefix("203.0.113.9/24"), "10m")
	if err != nil {
		t.Fatalf("leasePrefixRule: %v", err)
	}
	want := "add element inet nwall lease4_24 { 203.0.113.0 timeout 10m }\n"
	if got != want {
		t.Fatalf("rule mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestLeasePrefixRuleStoresIPv4HostIn32Set(t *testing.T) {
	got, err := leasePrefixRule(netip.MustParsePrefix("203.0.113.9/32"), "10m")
	if err != nil {
		t.Fatalf("leasePrefixRule: %v", err)
	}
	want := "add element inet nwall lease4_32 { 203.0.113.9 timeout 10m }\n"
	if got != want {
		t.Fatalf("rule mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestLeasePrefixRuleRejectsLargeIPv4Prefix(t *testing.T) {
	if _, err := leasePrefixRule(netip.MustParsePrefix("203.0.112.0/23"), "10m"); err == nil {
		t.Fatal("IPv4 /23 应拒绝")
	}
}
