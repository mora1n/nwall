package lease

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mora1n/nwall/internal/conf"
)

func TestAgentAddsSourceCIDRLease(t *testing.T) {
	agent := newTestAgent(t)
	var gotPrefix netip.Prefix
	var gotTTL string
	agent.addLease = func(p netip.Prefix, ttl string) error {
		gotPrefix = p
		gotTTL = ttl
		return nil
	}
	resp, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, signedRequest("secret", "office", "203.0.113.9", "", "", "n1")))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !resp.OK || resp.LeaseCIDR != "203.0.113.0/24" {
		t.Fatalf("响应不符: %+v", resp)
	}
	if gotPrefix.String() != "203.0.113.0/24" || gotTTL != "5m" {
		t.Fatalf("lease 写入不符: %s ttl=%s", gotPrefix, gotTTL)
	}
}

func TestAgentMaskOverridesLeasePrefix(t *testing.T) {
	agent := newTestAgent(t)
	var gotPrefix netip.Prefix
	agent.addLease = func(p netip.Prefix, _ string) error {
		gotPrefix = p
		return nil
	}
	resp, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, signedRequest("secret", "office", "203.0.113.9", "32", "", "n1")))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !resp.OK || gotPrefix.String() != "203.0.113.9/32" {
		t.Fatalf("mask=32 应写入单 IP，resp=%+v prefix=%s", resp, gotPrefix)
	}
}

func TestAgentRejectsUntrustedRelay(t *testing.T) {
	agent := newTestAgent(t)
	agent.addLease = func(netip.Prefix, string) error { return nil }
	if _, err := agent.handle(testAddr("192.0.2.7:12345"), decoderFor(t, signedRequest("secret", "office", "203.0.113.9", "", "", "n1"))); err == nil {
		t.Fatal("非可信 relay 应拒绝")
	}
}

func TestAgentRejectsInvalidSignature(t *testing.T) {
	agent := newTestAgent(t)
	agent.addLease = func(netip.Prefix, string) error { return nil }
	req := signedRequest("wrong-secret", "office", "203.0.113.9", "", "", "n1")
	if _, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, req)); err == nil {
		t.Fatal("签名错误应拒绝")
	}
}

func TestAgentRejectsReplay(t *testing.T) {
	agent := newTestAgent(t)
	agent.addLease = func(netip.Prefix, string) error { return nil }
	req := signedRequest("secret", "office", "203.0.113.9", "", "", "n1")
	if _, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, req)); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if _, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, req)); err == nil {
		t.Fatal("重复 nonce 应拒绝")
	}
}

func TestAgentChecksObservedIPBeforeMask(t *testing.T) {
	cfg := conf.Default()
	cfg.Lease.LeaseKey = "secret"
	cfg.Lease.TrustedRelayCIDRs = []string{"198.51.100.0/24"}
	cfg.Lease.Routes = []conf.Route{{Label: "office", IdleTTL: "5m", IPAllowCIDRs: []string{"203.0.113.9/32"}}}
	agent, err := NewAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	agent.now = func() time.Time { return time.Unix(100, 0) }
	agent.addLease = func(netip.Prefix, string) error { return nil }
	if _, err := agent.handle(testAddr("198.51.100.7:12345"), decoderFor(t, signedRequest("secret", "office", "203.0.113.9", "24", "", "n1"))); err != nil {
		t.Fatalf("observed IP 命中 allow 时应通过: %v", err)
	}
}

func TestLeasePrefixMaskValidation(t *testing.T) {
	route := conf.Route{IPv4PrefixLen: 24, IPv6PrefixLen: 128}
	prefix, err := leasePrefix("203.0.113.9", route, "/24")
	if err != nil {
		t.Fatalf("IPv4 /24 应通过: %v", err)
	}
	if prefix.String() != "203.0.113.0/24" {
		t.Fatalf("IPv4 /24 结果不符: %s", prefix)
	}
	if _, err := leasePrefix("203.0.113.9", route, "16"); err == nil {
		t.Fatal("IPv4 /16 应拒绝")
	}
	if _, err := leasePrefix("2001:db8::9", conf.Route{IPv6PrefixLen: 128}, "64"); err == nil {
		t.Fatal("IPv6 /64 应拒绝")
	}
}

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	cfg := conf.Default()
	cfg.Lease.LeaseKey = "secret"
	cfg.Lease.TrustedRelayCIDRs = []string{"198.51.100.0/24"}
	cfg.Lease.Routes = []conf.Route{{Label: "office", IdleTTL: "5m"}}
	agent, err := NewAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	agent.now = func() time.Time { return time.Unix(100, 0) }
	return agent
}

func signedRequest(key, label, sourceIP, mask, idleTTL, nonce string) Request {
	req := Request{
		Version:  protocolVersion,
		Label:    label,
		SourceIP: sourceIP,
		Mask:     mask,
		IdleTTL:  idleTTL,
		TS:       100,
		Nonce:    nonce,
	}
	req.Signature = signRequest(key, req)
	return req
}

func decoderFor(t *testing.T, req Request) *json.Decoder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		t.Fatal(err)
	}
	return json.NewDecoder(&buf)
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

var _ net.Addr = testAddr("")

func TestSignatureBaseIsStable(t *testing.T) {
	req := signedRequest("secret", "office", "203.0.113.9", "24", "3d", "n1")
	got := signatureBase(req)
	want := "v1|office|203.0.113.9|24|3d|100|n1"
	if !strings.EqualFold(got, want) {
		t.Fatalf("signature base 不符: %q", got)
	}
}

func TestTriggerUsesTrustedProxyHeader(t *testing.T) {
	trigger := newTestTrigger(t)
	var got SendOptions
	trigger.sendLease = func(_ context.Context, opts SendOptions) (Response, error) {
		got = opts
		return Response{OK: true, Label: opts.Label, ObservedIP: opts.SourceIP, LeaseCIDR: "203.0.113.0/24", IdleTTL: opts.IdleTTL}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "http://trigger.local/test-token", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rec := httptest.NewRecorder()
	trigger.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got.Target != "198.51.100.7:19082" || got.Label != "office" || got.SourceIP != "203.0.113.9" || got.Mask != "24" || got.IdleTTL != "3d" || got.Key != "secret" {
		t.Fatalf("send opts 不符: %+v", got)
	}
}

func TestTriggerMaskOverride(t *testing.T) {
	trigger := newTestTrigger(t)
	var gotMask string
	trigger.sendLease = func(_ context.Context, opts SendOptions) (Response, error) {
		gotMask = opts.Mask
		return Response{OK: true, Label: opts.Label, ObservedIP: opts.SourceIP, LeaseCIDR: "203.0.113.9/32", IdleTTL: opts.IdleTTL}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "http://trigger.local/test-token?mask=32", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.10")
	rec := httptest.NewRecorder()
	trigger.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotMask != "32" {
		t.Fatalf("mask 覆盖不符: %q", gotMask)
	}
}

func TestTriggerUnknownTokenReturns404(t *testing.T) {
	trigger := newTestTrigger(t)
	req := httptest.NewRequest(http.MethodGet, "http://trigger.local/missing", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	trigger.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token 应返回 404，got=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTriggerIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	trigger := newTestTrigger(t)
	var gotSource string
	trigger.sendLease = func(_ context.Context, opts SendOptions) (Response, error) {
		gotSource = opts.SourceIP
		return Response{OK: true, Label: opts.Label, ObservedIP: opts.SourceIP, LeaseCIDR: "198.51.100.9/32", IdleTTL: opts.IdleTTL}, nil
	}
	req := httptest.NewRequest(http.MethodGet, "http://trigger.local/test-token?mask=32", nil)
	req.RemoteAddr = "198.51.100.9:12345"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rec := httptest.NewRecorder()
	trigger.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotSource != "198.51.100.9" {
		t.Fatalf("非可信 peer 不应信任 header，got=%q", gotSource)
	}
}

func newTestTrigger(t *testing.T) *Trigger {
	t.Helper()
	cfg := conf.Default()
	cfg.Lease.LeaseKey = "secret"
	cfg.Lease.IdleTTL = "10m"
	cfg.LeaseTrigger.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	cfg.LeaseTrigger.Routes = []conf.TriggerRoute{{
		Token:         "test-token",
		Label:         "office",
		Target:        "198.51.100.7:19082",
		IdleTTL:       "3d",
		IPv4PrefixLen: 24,
		IPv6PrefixLen: 128,
	}}
	trigger, err := NewTrigger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return trigger
}
