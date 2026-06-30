// Package ingress 组装入站白名单来源 CIDR（自定义 + CN 省/市 geo），供 nft 渲染。
package ingress

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

// Sources 是入站白名单展开后的 IPv4/IPv6 前缀集合。
type Sources struct {
	V4    []netip.Prefix
	V6    []netip.Prefix
	Ports []PortSources
}

// PortSources 是单个监听端口覆盖策略展开后的白名单来源。
type PortSources struct {
	ListenPort int
	V4         []netip.Prefix
	V6         []netip.Prefix
}

// Build 把 ingress 配置展开为白名单来源前缀（自定义 CIDR + CN 省份 + CN 城市）。
// db 为 nil 时仅展开自定义 CIDR（便于无 geo 测试）。
func Build(cfg conf.Ingress, db *geo.DB) (Sources, error) {
	var s Sources
	for _, raw := range cfg.CustomCIDRs {
		p, err := parsePrefix(raw)
		if err != nil {
			return Sources{}, fmt.Errorf("custom_cidrs: %w", err)
		}
		s.add(p)
	}
	if err := addGeoSources(&s, cfg.CNMode, cfg.CNProvinces, cfg.CNCityCodes, db); err != nil {
		return Sources{}, err
	}
	for _, policy := range sortedPolicies(cfg.PortPolicies) {
		var portSrc PortSources
		portSrc.ListenPort = policy.ListenPort
		if err := addGeoSources(&portSrc, policy.CNMode, policy.CNProvinces, policy.CNCityCodes, db); err != nil {
			return Sources{}, fmt.Errorf("port %d: %w", policy.ListenPort, err)
		}
		s.Ports = append(s.Ports, portSrc)
	}
	return s, nil
}

func (s *Sources) add(p netip.Prefix) {
	if p.Addr().Is4() {
		s.V4 = append(s.V4, p)
	} else {
		s.V6 = append(s.V6, p)
	}
}

func (s *PortSources) add(p netip.Prefix) {
	if p.Addr().Is4() {
		s.V4 = append(s.V4, p)
	} else {
		s.V6 = append(s.V6, p)
	}
}

func addGeoSources(dst interface{ add(netip.Prefix) }, mode string, provinces, cityCodes []string, db *geo.DB) error {
	if (mode != "off" && mode != "") || len(cityCodes) > 0 {
		if db == nil {
			return fmt.Errorf("需要 geo 库但未加载")
		}
	}
	if mode != "off" && mode != "" {
		provs, err := db.ExportProvinces(mode, provinces)
		if err != nil {
			return err
		}
		for _, p := range provs {
			dst.add(p)
		}
	}
	if len(cityCodes) > 0 {
		cities, err := db.ExportCities(cityCodes)
		if err != nil {
			return err
		}
		for _, p := range cities {
			dst.add(p)
		}
	}
	return nil
}

func sortedPolicies(in []conf.PortPolicy) []conf.PortPolicy {
	out := append([]conf.PortPolicy(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ListenPort < out[j].ListenPort
	})
	return out
}

// parsePrefix 接受单个 IP 或 CIDR，统一规整为已掩码前缀。
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
