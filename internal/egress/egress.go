// Package egress 组装出站白名单 CIDR（特殊网络 + 网关/onlink + 自定义 + CN geo）。
package egress

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

// Sources 是出站白名单展开后的 IPv4/IPv6 前缀集合。
type Sources struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// Build 展开 egress 配置。启用时总是包含特殊网络、默认网关与 onlink 地址。
func Build(cfg conf.Egress, db *geo.DB) (Sources, error) {
	var s Sources
	for _, raw := range specialCIDRs() {
		if err := addPrefix(&s, raw); err != nil {
			return Sources{}, err
		}
	}
	host, err := HostCIDRs()
	if err != nil {
		return Sources{}, err
	}
	for _, p := range host {
		s.add(p)
	}
	for _, raw := range cfg.CustomCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return Sources{}, fmt.Errorf("custom_cidrs: %w", err)
		}
		s.add(p)
	}
	if cfg.CNMode != "off" && cfg.CNMode != "" {
		if db == nil {
			return Sources{}, fmt.Errorf("需要 geo 库但未加载")
		}
		provs, err := db.ExportProvinces(cfg.CNMode, cfg.CNProvinces)
		if err != nil {
			return Sources{}, err
		}
		for _, p := range provs {
			s.add(p)
		}
	}
	return s, nil
}

// HostCIDRs 返回默认网关 IP 与非 lo 全局 onlink 前缀。
func HostCIDRs() ([]netip.Prefix, error) {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil, fmt.Errorf("缺少 ip 命令，无法探测 egress 网关/onlink: %w", err)
	}
	rows, err := ipOutput("-o", "addr", "show", "up", "scope", "global")
	if err != nil {
		return nil, err
	}
	out := []netip.Prefix{}
	for _, p := range parseOnlinkCIDRs(rows) {
		out = append(out, p)
	}
	v4gw, err := ipOutput("route", "show", "default")
	if err != nil {
		return nil, err
	}
	v6gw, err := ipOutput("-6", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	for _, p := range parseGatewayCIDRs(v4gw + "\n" + v6gw) {
		out = append(out, p)
	}
	return out, nil
}

func ipOutput(args ...string) (string, error) {
	cmd := exec.Command("ip", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("执行 ip %s 失败: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func parseOnlinkCIDRs(raw string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] == "lo" {
			continue
		}
		for i, f := range fields {
			if (f == "inet" || f == "inet6") && i+1 < len(fields) {
				if p, err := netip.ParsePrefix(stripZone(fields[i+1])); err == nil {
					out = append(out, p.Masked())
				}
			}
		}
	}
	return out
}

func parseGatewayCIDRs(raw string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				if addr, err := netip.ParseAddr(stripZone(fields[i+1])); err == nil {
					bits := 128
					if addr.Is4() {
						bits = 32
					}
					out = append(out, netip.PrefixFrom(addr, bits))
				}
			}
		}
	}
	return out
}

func stripZone(raw string) string {
	return strings.Split(strings.TrimSpace(raw), "%")[0]
}

func specialCIDRs() []string {
	return []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
		"ff00::/8",
	}
}

func addPrefix(s *Sources, raw string) error {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return err
	}
	s.add(p.Masked())
	return nil
}

func (s *Sources) add(p netip.Prefix) {
	if p.Addr().Is4() {
		s.V4 = append(s.V4, p)
	} else {
		s.V6 = append(s.V6, p)
	}
}

func parsePrefix(raw string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("无效 IP/CIDR: %s", raw)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}
