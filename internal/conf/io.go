package conf

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ApplyFallbacks fills zero-valued optional fields with runtime defaults.
func ApplyFallbacks(cfg *Config) {
	if cfg.Protect.RollbackTimeoutSec <= 0 {
		cfg.Protect.RollbackTimeoutSec = 10
	}
	if cfg.Ingress.CNMode == "" {
		cfg.Ingress.CNMode = "off"
	}
	for i := range cfg.Ingress.PortPolicies {
		if cfg.Ingress.PortPolicies[i].CNMode == "" {
			cfg.Ingress.PortPolicies[i].CNMode = "off"
		}
	}
	if cfg.Egress.CNMode == "" {
		cfg.Egress.CNMode = "off"
	}
	if cfg.Lease.IdleTTL == "" {
		cfg.Lease.IdleTTL = "3d"
	}
	if cfg.Lease.ListenHost == "" {
		cfg.Lease.ListenHost = "127.0.0.1"
	}
	if cfg.Lease.ListenPort == 0 {
		cfg.Lease.ListenPort = 18080
	}
	if cfg.Lease.TSWindowSec <= 0 {
		cfg.Lease.TSWindowSec = 60
	}
	if cfg.LeaseTrigger.Enabled {
		if cfg.LeaseTrigger.ListenHost == "" {
			cfg.LeaseTrigger.ListenHost = "127.0.0.1"
		}
		if cfg.LeaseTrigger.ListenPort == 0 {
			cfg.LeaseTrigger.ListenPort = 18081
		}
	}
}

// Validate 校验配置语义正确性。
func Validate(cfg Config) error {
	if err := validateCNMode(cfg.Ingress.CNMode); err != nil {
		return fmt.Errorf("ingress.cn_mode %w", err)
	}
	if err := validateCNMode(cfg.Egress.CNMode); err != nil {
		return fmt.Errorf("egress.cn_mode %w", err)
	}
	if err := validateLeaseTTL(cfg.Lease.IdleTTL); err != nil {
		return fmt.Errorf("lease.idle_ttl 无效: %w", err)
	}
	if err := validatePort(cfg.Lease.ListenPort); err != nil {
		return fmt.Errorf("lease.listen_port: %w", err)
	}
	for i, raw := range cfg.Ingress.CustomCIDRs {
		if err := validateCIDRLike(raw); err != nil {
			return fmt.Errorf("ingress.custom_cidrs[%d]: %w", i, err)
		}
	}
	for i, raw := range cfg.Egress.CustomCIDRs {
		if err := validateCIDRLike(raw); err != nil {
			return fmt.Errorf("egress.custom_cidrs[%d]: %w", i, err)
		}
	}
	seenPorts := map[int]struct{}{}
	for i, p := range cfg.Ingress.PortPolicies {
		if err := validatePort(p.ListenPort); err != nil {
			return fmt.Errorf("ingress.port_policies[%d].listen_port: %w", i, err)
		}
		if _, ok := seenPorts[p.ListenPort]; ok {
			return fmt.Errorf("ingress.port_policies[%d].listen_port 重复: %d", i, p.ListenPort)
		}
		seenPorts[p.ListenPort] = struct{}{}
		if err := validateCNMode(p.CNMode); err != nil {
			return fmt.Errorf("ingress.port_policies[%d].cn_mode %w", i, err)
		}
	}
	for _, p := range cfg.Protect.OpenPorts {
		if err := validatePort(p); err != nil {
			return fmt.Errorf("protect.open_ports: %w", err)
		}
	}
	for _, r := range cfg.Protect.OpenPortRanges {
		if err := validatePort(r.Start); err != nil {
			return fmt.Errorf("protect.open_port_ranges: %w", err)
		}
		if err := validatePort(r.End); err != nil {
			return fmt.Errorf("protect.open_port_ranges: %w", err)
		}
		if r.Start > r.End {
			return fmt.Errorf("protect.open_port_ranges: 起始端口不能大于结束端口")
		}
	}
	for _, p := range cfg.Protect.GuardedPorts {
		if err := validatePort(p); err != nil {
			return fmt.Errorf("protect.guarded_ports: %w", err)
		}
	}
	for _, p := range cfg.Protect.ProtocolSkipPorts {
		if err := validatePort(p); err != nil {
			return fmt.Errorf("protect.protocol_skip_ports: %w", err)
		}
	}
	for i, r := range cfg.Lease.Routes {
		if r.Label == "" {
			return fmt.Errorf("lease.routes[%d].label 不能为空", i)
		}
		if r.IdleTTL != "" {
			if err := validateLeaseTTL(r.IdleTTL); err != nil {
				return fmt.Errorf("lease.routes[%d].idle_ttl 无效: %w", i, err)
			}
		}
		if err := validateIPv4LeasePrefixLen(r.IPv4PrefixLen); err != nil {
			return fmt.Errorf("lease.routes[%d].%w", i, err)
		}
		if err := validateIPv6LeasePrefixLen(r.IPv6PrefixLen); err != nil {
			return fmt.Errorf("lease.routes[%d].%w", i, err)
		}
		for j, raw := range r.IPAllowCIDRs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("lease.routes[%d].ip_allow_cidrs[%d] 无效: %s", i, j, raw)
			}
		}
	}
	for i, raw := range cfg.Lease.TrustedRelayCIDRs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("lease.trusted_relay_cidrs[%d] 无效: %s", i, raw)
		}
	}
	if cfg.LeaseTrigger.Enabled {
		if strings.TrimSpace(cfg.LeaseTrigger.ListenHost) == "" {
			return fmt.Errorf("lease_trigger.listen_host 不能为空")
		}
		if err := validatePort(cfg.LeaseTrigger.ListenPort); err != nil {
			return fmt.Errorf("lease_trigger.listen_port: %w", err)
		}
	}
	for i, raw := range cfg.LeaseTrigger.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("lease_trigger.trusted_proxy_cidrs[%d] 无效: %s", i, raw)
		}
	}
	for i, r := range cfg.LeaseTrigger.Routes {
		if strings.TrimSpace(r.Token) == "" {
			return fmt.Errorf("lease_trigger.routes[%d].token 不能为空", i)
		}
		if strings.Contains(r.Token, "/") {
			return fmt.Errorf("lease_trigger.routes[%d].token 不能包含 /", i)
		}
		if strings.TrimSpace(r.Label) == "" {
			return fmt.Errorf("lease_trigger.routes[%d].label 不能为空", i)
		}
		if strings.TrimSpace(r.Target) == "" {
			return fmt.Errorf("lease_trigger.routes[%d].target 不能为空", i)
		}
		host, port, err := net.SplitHostPort(r.Target)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return fmt.Errorf("lease_trigger.routes[%d].target 必须是 HOST:PORT", i)
		}
		if r.IdleTTL != "" {
			if err := validateLeaseTTL(r.IdleTTL); err != nil {
				return fmt.Errorf("lease_trigger.routes[%d].idle_ttl 无效: %w", i, err)
			}
		}
		if err := validateIPv4LeasePrefixLen(r.IPv4PrefixLen); err != nil {
			return fmt.Errorf("lease_trigger.routes[%d].%w", i, err)
		}
		if err := validateIPv6LeasePrefixLen(r.IPv6PrefixLen); err != nil {
			return fmt.Errorf("lease_trigger.routes[%d].%w", i, err)
		}
	}
	return nil
}

func validateCNMode(mode string) error {
	switch mode {
	case "off", "all", "provinces":
		return nil
	default:
		return fmt.Errorf("必须是 off|all|provinces，当前=%q", mode)
	}
}

func validatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("端口越界: %d", p)
	}
	return nil
}

func validateCIDRLike(raw string) error {
	if _, err := netip.ParsePrefix(raw); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return nil
	}
	return fmt.Errorf("无效 IP/CIDR: %s", raw)
}

func validateIPv4LeasePrefixLen(value int) error {
	if value == 0 {
		return nil
	}
	if value < 24 || value > 32 {
		return fmt.Errorf("ipv4_prefix_len 当前仅支持 0 或 24-32")
	}
	return nil
}

func validateIPv6LeasePrefixLen(value int) error {
	if value == 0 {
		return nil
	}
	if value != 128 {
		return fmt.Errorf("ipv6_prefix_len 当前仅支持 0 或 128")
	}
	return nil
}

func validateLeaseTTL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("不能为空")
	}
	if _, err := time.ParseDuration(raw); err == nil {
		return nil
	}
	if !strings.HasSuffix(raw, "d") {
		return fmt.Errorf("必须是 Go duration 或整数天，例如 10m、1h、3d")
	}
	days, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
	if err != nil || days <= 0 {
		return fmt.Errorf("无效天数: %s", raw)
	}
	return nil
}
