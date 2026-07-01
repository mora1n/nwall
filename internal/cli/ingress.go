package cli

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

// runIngress 处理 `nwall ingress ...` 子命令（改配置后需 protect apply 生效）。
func runIngress(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress enable|disable|status|cn|city|custom ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "enable":
		cfg.Ingress.Enabled = true
		return saveIngress(cfg, "入站白名单已启用（执行 nwall protect apply 生效）")
	case "disable":
		cfg.Ingress.Enabled = false
		return saveIngress(cfg, "入站白名单已停用（执行 nwall protect apply 生效）")
	case "status":
		fmt.Printf("enabled: %v\ncn_mode: %s\ncn_provinces: %v\ncn_city_codes: %v\ncustom_cidrs: %v\n",
			cfg.Ingress.Enabled, cfg.Ingress.CNMode, cfg.Ingress.CNProvinces, cfg.Ingress.CNCityCodes, cfg.Ingress.CustomCIDRs)
		return nil
	case "cn":
		return ingressCN(cfg, args[1:])
	case "city":
		return ingressCity(cfg, args[1:])
	case "custom":
		return ingressCustom(cfg, args[1:])
	case "port":
		return ingressPort(cfg, args[1:])
	default:
		return fmt.Errorf("未知 ingress 子命令: %s", args[0])
	}
}

func ingressCN(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress cn off|all|list|select <省份...>")
	}
	switch args[0] {
	case "off":
		cfg.Ingress.CNMode = "off"
		cfg.Ingress.CNProvinces = nil
		return saveIngress(cfg, "已关闭 CN 入站策略")
	case "all":
		cfg.Ingress.CNMode = "all"
		cfg.Ingress.CNProvinces = nil
		return saveIngress(cfg, "已设为放行全部 CN IP")
	case "list":
		db, err := geo.Default()
		if err != nil {
			return err
		}
		provs := db.Provinces()
		for _, p := range provs {
			fmt.Println(p)
		}
		return nil
	case "select":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress cn select <省份...>")
		}
		db, err := geo.Default()
		if err != nil {
			return err
		}
		for _, name := range args[1:] {
			if !db.ProvinceExists(name) {
				return fmt.Errorf("未知省份: %s", name)
			}
		}
		cfg.Ingress.CNMode = "provinces"
		cfg.Ingress.CNProvinces = args[1:]
		return saveIngress(cfg, "已设为按省份放行: "+strings.Join(args[1:], ", "))
	default:
		return fmt.Errorf("未知 cn 子命令: %s", args[0])
	}
}

func ingressCity(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress city list|add|del <code...>")
	}
	switch args[0] {
	case "list":
		return printCityCodes(cfg.Ingress.CNCityCodes)
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress city add <code...>")
		}
		if err := validateCityCodes(args[1:]); err != nil {
			return err
		}
		cfg.Ingress.CNCityCodes = appendUnique(cfg.Ingress.CNCityCodes, args[1:]...)
		return saveIngress(cfg, "已添加城市 code: "+strings.Join(args[1:], ", "))
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress city del <code...>")
		}
		next, err := removeValues(cfg.Ingress.CNCityCodes, args[1:]...)
		if err != nil {
			return err
		}
		cfg.Ingress.CNCityCodes = next
		return saveIngress(cfg, "已删除城市 code: "+strings.Join(args[1:], ", "))
	default:
		return fmt.Errorf("未知 city 子命令: %s", args[0])
	}
}

func ingressCustom(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress custom add|del|list <IP/CIDR...>")
	}
	switch args[0] {
	case "list":
		for _, c := range cfg.Ingress.CustomCIDRs {
			fmt.Println(c)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress custom add <IP/CIDR...>")
		}
		cidrs, err := canonicalCIDRArgs(args[1:]...)
		if err != nil {
			return err
		}
		cfg.Ingress.CustomCIDRs = appendUnique(cfg.Ingress.CustomCIDRs, cidrs...)
		return saveIngress(cfg, "已添加自定义 CIDR: "+strings.Join(cidrs, ", "))
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress custom del <IP/CIDR...>")
		}
		cidrs, err := canonicalCIDRArgs(args[1:]...)
		if err != nil {
			return err
		}
		out, err := removeValues(cfg.Ingress.CustomCIDRs, cidrs...)
		if err != nil {
			return fmt.Errorf("未找到 CIDR: %s", strings.Join(cidrs, ", "))
		}
		cfg.Ingress.CustomCIDRs = out
		return saveIngress(cfg, "已删除自定义 CIDR: "+strings.Join(cidrs, ", "))
	default:
		return fmt.Errorf("未知 custom 子命令: %s", args[0])
	}
}

func ingressPort(cfg conf.Config, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("用法: nwall ingress port <port> status|clear|cn|city ...")
	}
	port, err := parsePort(args[0])
	if err != nil {
		return err
	}
	switch args[1] {
	case "status":
		return printPortPolicyStatus(cfg, port)
	case "clear":
		if !portPolicyExists(cfg.Ingress.PortPolicies, port) {
			return fmt.Errorf("未找到端口覆盖策略: %d", port)
		}
		cfg.Ingress.PortPolicies = removePortPolicy(cfg.Ingress.PortPolicies, port)
		return saveIngress(cfg, fmt.Sprintf("已清除端口 %d 覆盖策略", port))
	case "cn":
		return ingressPortCN(cfg, port, args[2:])
	case "city":
		return ingressPortCity(cfg, port, args[2:])
	default:
		return fmt.Errorf("未知 port 子命令: %s", args[1])
	}
}

func ingressPortCN(cfg conf.Config, port int, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress port <port> cn off|all|select <省份...>")
	}
	policy := portPolicyBase(cfg, port)
	switch args[0] {
	case "off":
		policy.CNMode = "off"
		policy.CNProvinces = nil
	case "all":
		policy.CNMode = "all"
		policy.CNProvinces = nil
	case "select":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress port <port> cn select <省份...>")
		}
		if err := validateProvinces(args[1:]); err != nil {
			return err
		}
		policy.CNMode = "provinces"
		policy.CNProvinces = append([]string(nil), args[1:]...)
	default:
		return fmt.Errorf("未知 port cn 子命令: %s", args[0])
	}
	cfg.Ingress.PortPolicies = upsertPortPolicy(cfg.Ingress.PortPolicies, policy)
	return saveIngress(cfg, fmt.Sprintf("已更新端口 %d CN 策略", port))
}

func ingressPortCity(cfg conf.Config, port int, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall ingress port <port> city list|add|del <code...>")
	}
	policy := portPolicyBase(cfg, port)
	switch args[0] {
	case "list":
		return printCityCodes(policy.CNCityCodes)
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress port <port> city add <code...>")
		}
		if err := validateCityCodes(args[1:]); err != nil {
			return err
		}
		policy.CNCityCodes = appendUnique(policy.CNCityCodes, args[1:]...)
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: nwall ingress port <port> city del <code...>")
		}
		next, err := removeValues(policy.CNCityCodes, args[1:]...)
		if err != nil {
			return err
		}
		policy.CNCityCodes = next
	default:
		return fmt.Errorf("未知 port city 子命令: %s", args[0])
	}
	cfg.Ingress.PortPolicies = upsertPortPolicy(cfg.Ingress.PortPolicies, policy)
	return saveIngress(cfg, fmt.Sprintf("已更新端口 %d 城市策略", port))
}

func saveIngress(cfg conf.Config, msg string) error {
	if err := saveConfigValue(cfg); err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("无效端口: %s", raw)
	}
	return port, nil
}

func validateProvinces(names []string) error {
	db, err := geo.Default()
	if err != nil {
		return err
	}
	for _, name := range names {
		if !db.ProvinceExists(name) {
			return fmt.Errorf("未知省份: %s", name)
		}
	}
	return nil
}

func validateCityCodes(codes []string) error {
	db, err := geo.Default()
	if err != nil {
		return err
	}
	for _, code := range codes {
		if !db.CityExists(code) {
			return fmt.Errorf("未知城市 code: %s", code)
		}
		if _, err := db.ExportCities([]string{code}); err != nil {
			return err
		}
	}
	return nil
}

func printCityCodes(codes []string) error {
	for _, code := range codes {
		fmt.Println(code)
	}
	return nil
}

func printPortPolicyStatus(cfg conf.Config, port int) error {
	policy := portPolicyBase(cfg, port)
	source := "全局默认"
	if portPolicyExists(cfg.Ingress.PortPolicies, port) {
		source = "端口覆盖"
	}
	fmt.Printf("listen_port: %d\nsource: %s\ncn_mode: %s\ncn_provinces: %v\ncn_city_codes: %v\n",
		port, source, policy.CNMode, policy.CNProvinces, policy.CNCityCodes)
	return nil
}

func portPolicyBase(cfg conf.Config, port int) conf.PortPolicy {
	for _, policy := range cfg.Ingress.PortPolicies {
		if policy.ListenPort == port {
			return clonePortPolicy(policy)
		}
	}
	return conf.PortPolicy{
		ListenPort:  port,
		CNMode:      cfg.Ingress.CNMode,
		CNProvinces: append([]string(nil), cfg.Ingress.CNProvinces...),
		CNCityCodes: append([]string(nil), cfg.Ingress.CNCityCodes...),
	}
}

func clonePortPolicy(policy conf.PortPolicy) conf.PortPolicy {
	return conf.PortPolicy{
		ListenPort:  policy.ListenPort,
		CNMode:      policy.CNMode,
		CNProvinces: append([]string(nil), policy.CNProvinces...),
		CNCityCodes: append([]string(nil), policy.CNCityCodes...),
	}
}

func portPolicyExists(policies []conf.PortPolicy, port int) bool {
	for _, policy := range policies {
		if policy.ListenPort == port {
			return true
		}
	}
	return false
}

func upsertPortPolicy(policies []conf.PortPolicy, policy conf.PortPolicy) []conf.PortPolicy {
	out := make([]conf.PortPolicy, 0, len(policies)+1)
	for _, current := range policies {
		if current.ListenPort != policy.ListenPort {
			out = append(out, clonePortPolicy(current))
		}
	}
	out = append(out, clonePortPolicy(policy))
	sort.Slice(out, func(i, j int) bool {
		return out[i].ListenPort < out[j].ListenPort
	})
	return out
}

func removePortPolicy(policies []conf.PortPolicy, port int) []conf.PortPolicy {
	out := make([]conf.PortPolicy, 0, len(policies))
	for _, policy := range policies {
		if policy.ListenPort != port {
			out = append(out, clonePortPolicy(policy))
		}
	}
	return out
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	out := make([]string, 0, len(values)+len(additions))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range additions {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func canonicalCIDRArgs(values ...string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		cidr, err := canonicalCIDR(value)
		if err != nil {
			return nil, err
		}
		out = append(out, cidr)
	}
	return appendUnique(nil, out...), nil
}

func canonicalCIDR(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("无效 IP/CIDR: %s", raw)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), nil
}

func removeValues(values []string, removals ...string) ([]string, error) {
	remove := make(map[string]struct{}, len(removals))
	for _, value := range removals {
		remove[value] = struct{}{}
	}
	found := make(map[string]struct{}, len(removals))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := remove[value]; ok {
			found[value] = struct{}{}
			continue
		}
		out = append(out, value)
	}
	for _, value := range removals {
		if _, ok := found[value]; !ok {
			return nil, fmt.Errorf("未找到: %s", value)
		}
	}
	return out, nil
}
