package conf

import "testing"

func TestApplyFallbacks(t *testing.T) {
	cfg := Config{}
	ApplyFallbacks(&cfg)
	if cfg.Protect.RollbackTimeoutSec != 10 {
		t.Errorf("rollback_timeout_sec 应回落 10，得 %d", cfg.Protect.RollbackTimeoutSec)
	}
	if cfg.Lease.ListenPort != 18080 || cfg.Lease.IdleTTL != "3d" || cfg.Lease.TSWindowSec != 60 {
		t.Errorf("lease 默认值回落失败: %+v", cfg.Lease)
	}
}

func TestValidateRejectsBadCNMode(t *testing.T) {
	cfg := Default()
	cfg.Ingress.CNMode = "bogus"
	if err := Validate(cfg); err == nil {
		t.Error("应拒绝非法 cn_mode")
	}
}

func TestValidateRejectsBadPort(t *testing.T) {
	cfg := Default()
	cfg.Protect.OpenPorts = []int{70000}
	if err := Validate(cfg); err == nil {
		t.Error("应拒绝越界端口")
	}
}

func TestValidateRejectsDuplicatePortPolicy(t *testing.T) {
	cfg := Default()
	cfg.Ingress.PortPolicies = []PortPolicy{
		{ListenPort: 8443, CNMode: "off"},
		{ListenPort: 8443, CNMode: "all"},
	}
	if err := Validate(cfg); err == nil {
		t.Error("应拒绝重复 listen_port 的端口策略")
	}
}

func TestValidateRejectsBadPortPolicyMode(t *testing.T) {
	cfg := Default()
	cfg.Ingress.PortPolicies = []PortPolicy{{ListenPort: 8443, CNMode: "bogus"}}
	if err := Validate(cfg); err == nil {
		t.Error("应拒绝端口策略非法 cn_mode")
	}
}

func TestValidateLease(t *testing.T) {
	cfg := Default()
	cfg.Lease.Routes = []Route{{Label: "office", IdleTTL: "5m", IPv4PrefixLen: 32, IPv6PrefixLen: 128, IPAllowCIDRs: []string{"203.0.113.0/24"}}}
	cfg.Lease.TrustedRelayCIDRs = []string{"198.51.100.0/24"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("合法 lease 应通过: %v", err)
	}
	cfg.Lease.Routes[0].IdleTTL = "bad"
	if err := Validate(cfg); err == nil {
		t.Fatal("非法 idle_ttl 应拒绝")
	}
}

func TestValidateLeaseAcceptsDays(t *testing.T) {
	cfg := Default()
	cfg.Lease.IdleTTL = "3d"
	cfg.Lease.Routes = []Route{{Label: "office", IdleTTL: "3d", IPv4PrefixLen: 24, IPv6PrefixLen: 128}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("整数天 lease TTL 应通过: %v", err)
	}
}

func TestValidateLeasePrefixLimits(t *testing.T) {
	cfg := Default()
	cfg.Lease.Routes = []Route{{Label: "office", IdleTTL: "5m", IPv4PrefixLen: 24, IPv6PrefixLen: 128}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("IPv4 /24 应通过: %v", err)
	}
	cfg.Lease.Routes[0].IPv4PrefixLen = 23
	if err := Validate(cfg); err == nil {
		t.Fatal("IPv4 /23 应拒绝")
	}
	cfg.Lease.Routes[0].IPv4PrefixLen = 24
	cfg.Lease.Routes[0].IPv6PrefixLen = 64
	if err := Validate(cfg); err == nil {
		t.Fatal("IPv6 /64 应拒绝")
	}
}
