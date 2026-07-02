package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/lease"
)

func runLease(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall lease server|route|trigger|trigger-route|send|keygen ...")
	}
	switch args[0] {
	case "server":
		return leaseConfig(args[1:])
	case "send":
		return leaseSend(args[1:])
	case "trigger":
		if len(args) > 1 && (args[1] == "set" || args[1] == "show") {
			return leaseTriggerConfig(args[1:])
		}
		return fmt.Errorf("用法: nwall lease trigger show|set ...")
	case "trigger-route":
		return leaseTriggerRoute(args[1:])
	case "route":
		return leaseRoute(args[1:])
	case "keygen":
		key, err := lease.Keygen()
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	default:
		return fmt.Errorf("未知 lease 子命令: %s", args[0])
	}
}

func leaseConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("listen: %s:%d\n", cfg.Lease.ListenHost, cfg.Lease.ListenPort)
		fmt.Printf("lease_key: %s\n", secretState(cfg.Lease.LeaseKey))
		fmt.Printf("idle_ttl: %s\n", cfg.Lease.IdleTTL)
		fmt.Printf("ts_window_sec: %d\n", cfg.Lease.TSWindowSec)
		fmt.Printf("trusted_relay_cidrs: %v\n", cfg.Lease.TrustedRelayCIDRs)
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("用法: nwall lease server show|set ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("lease server set", flag.ContinueOnError)
	listen := fs.String("listen", "", "监听地址 HOST:PORT")
	leaseKey := fs.String("lease-key", "", "TCP 租约共享 key，可用 nwall lease keygen 生成")
	idleTTL := fs.String("idle-ttl", "", "默认租约时长，如 3d")
	tsWindow := fs.Int("ts-window-sec", 0, "签名时间窗秒数")
	var trustedRelay multiFlag
	fs.Var(&trustedRelay, "trusted-relay", "可信 TCP relay IP/CIDR，可重复")
	clearTrustedRelay := fs.Bool("clear-trusted-relay", false, "清空可信 TCP relay CIDR")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *listen != "" {
		host, port, err := splitListen(*listen)
		if err != nil {
			return err
		}
		cfg.Lease.ListenHost = host
		cfg.Lease.ListenPort = port
	}
	if *leaseKey != "" {
		cfg.Lease.LeaseKey = *leaseKey
	}
	if *idleTTL != "" {
		cfg.Lease.IdleTTL = *idleTTL
	}
	if *tsWindow > 0 {
		cfg.Lease.TSWindowSec = *tsWindow
	}
	if *clearTrustedRelay {
		cfg.Lease.TrustedRelayCIDRs = nil
	}
	if len(trustedRelay) > 0 {
		cidrs, err := canonicalCIDRArgs([]string(trustedRelay)...)
		if err != nil {
			return err
		}
		cfg.Lease.TrustedRelayCIDRs = appendUnique(cfg.Lease.TrustedRelayCIDRs, cidrs...)
	}
	return saveConfig(cfg, "已更新 lease 配置")
}

func leaseSend(args []string) error {
	fs := flag.NewFlagSet("lease send", flag.ContinueOnError)
	target := fs.String("target", "", "目标 TCP agent，格式 HOST:PORT")
	label := fs.String("route", "", "临时放行路由 label")
	sourceIP := fs.String("source-ip", "", "要放行的来源 IP")
	mask := fs.String("mask", "", "租约掩码，IPv4 24-32；32 表示单 IP")
	idleTTL := fs.String("idle-ttl", "", "本次租约时长，如 3d/10m；为空使用 route 默认值")
	leaseKey := fs.String("lease-key", "", "TCP 租约共享 key；为空则读取本机 DB")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key := *leaseKey
	if key == "" {
		key = cfg.Lease.LeaseKey
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := lease.Send(ctx, lease.SendOptions{
		Target:   *target,
		Label:    *label,
		SourceIP: *sourceIP,
		Mask:     *mask,
		IdleTTL:  *idleTTL,
		Key:      key,
	})
	if err != nil {
		return err
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func leaseTriggerConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("listen: %s:%d\n", cfg.LeaseTrigger.ListenHost, cfg.LeaseTrigger.ListenPort)
		fmt.Printf("trusted_proxy_cidrs: %v\n", cfg.LeaseTrigger.TrustedProxyCIDRs)
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("用法: nwall lease trigger show|set ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("lease trigger set", flag.ContinueOnError)
	listen := fs.String("listen", "", "监听地址 HOST:PORT")
	var trustedProxy multiFlag
	fs.Var(&trustedProxy, "trusted-proxy", "可信反代 IP/CIDR，可重复")
	clearTrustedProxy := fs.Bool("clear-trusted-proxy", false, "清空可信反代 CIDR")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *listen != "" {
		host, port, err := splitListen(*listen)
		if err != nil {
			return err
		}
		cfg.LeaseTrigger.ListenHost = host
		cfg.LeaseTrigger.ListenPort = port
	}
	if *clearTrustedProxy {
		cfg.LeaseTrigger.TrustedProxyCIDRs = nil
	}
	if len(trustedProxy) > 0 {
		cidrs, err := canonicalCIDRArgs([]string(trustedProxy)...)
		if err != nil {
			return err
		}
		cfg.LeaseTrigger.TrustedProxyCIDRs = appendUnique(cfg.LeaseTrigger.TrustedProxyCIDRs, cidrs...)
	}
	return saveConfig(cfg, "已更新 lease trigger 配置")
}

func leaseTriggerRoute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall lease trigger-route add|del|list ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		for _, r := range cfg.LeaseTrigger.Routes {
			fmt.Printf("%s\t%s\t%s\t%s\tv4/%d\tv6/%d\n", r.Token, r.Label, r.Target, valueOr(r.IdleTTL, cfg.Lease.IdleTTL), routeV4LenFromValue(r.IPv4PrefixLen), routeV6LenFromValue(r.IPv6PrefixLen))
		}
		return nil
	case "del":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall lease trigger-route del <token>")
		}
		next := cfg.LeaseTrigger.Routes[:0]
		found := false
		for _, r := range cfg.LeaseTrigger.Routes {
			if r.Token == args[1] {
				found = true
				continue
			}
			next = append(next, r)
		}
		if !found {
			return fmt.Errorf("未找到 token 路由: %s", args[1])
		}
		cfg.LeaseTrigger.Routes = next
		return saveConfig(cfg, "已删除 token 路由: "+args[1])
	case "add":
		return leaseTriggerRouteAdd(cfg, args[1:])
	default:
		return fmt.Errorf("未知 lease trigger-route 子命令: %s", args[0])
	}
}

func leaseTriggerRouteAdd(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall lease trigger-route add <token> --label <label> --target HOST:PORT [--idle-ttl 3d] [--ipv4-prefix-len 24] [--ipv6-prefix-len 128]")
	}
	token := args[0]
	fs := flag.NewFlagSet("lease trigger-route add", flag.ContinueOnError)
	label := fs.String("label", "", "安装机临时放行路由 label")
	target := fs.String("target", "", "目标 TCP agent，格式 HOST:PORT")
	idleTTL := fs.String("idle-ttl", cfg.Lease.IdleTTL, "idle ttl")
	v4 := fs.Int("ipv4-prefix-len", 24, "IPv4 lease prefix length, 24-32")
	v6 := fs.Int("ipv6-prefix-len", 128, "IPv6 lease prefix length, only 128")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg.LeaseTrigger.Routes = upsertTriggerRoute(cfg.LeaseTrigger.Routes, conf.TriggerRoute{
		Token:         token,
		Label:         *label,
		Target:        *target,
		IdleTTL:       *idleTTL,
		IPv4PrefixLen: *v4,
		IPv6PrefixLen: *v6,
	})
	return saveConfig(cfg, "已写入 token 路由: "+token)
}

func leaseRoute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall lease route add|del|list ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		for _, r := range cfg.Lease.Routes {
			fmt.Printf("%s\t%s\tv4/%d\tv6/%d\t%v\n", r.Label, valueOr(r.IdleTTL, cfg.Lease.IdleTTL), routeV4Len(r), routeV6Len(r), r.IPAllowCIDRs)
		}
		return nil
	case "del":
		if len(args) != 2 {
			return fmt.Errorf("用法: nwall lease route del <label>")
		}
		next := cfg.Lease.Routes[:0]
		found := false
		for _, r := range cfg.Lease.Routes {
			if r.Label == args[1] {
				found = true
				continue
			}
			next = append(next, r)
		}
		if !found {
			return fmt.Errorf("未找到 route: %s", args[1])
		}
		cfg.Lease.Routes = next
		return saveConfig(cfg, "已删除临时放行路由: "+args[1])
	case "add":
		return leaseRouteAdd(cfg, args[1:])
	default:
		return fmt.Errorf("未知 lease route 子命令: %s", args[0])
	}
}

func leaseRouteAdd(cfg conf.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall lease route add <label> [--idle-ttl 3d] [--ipv4-prefix-len 24] [--ipv6-prefix-len 128] [--allow IP/CIDR]")
	}
	label := args[0]
	fs := flag.NewFlagSet("lease route add", flag.ContinueOnError)
	idleTTL := fs.String("idle-ttl", cfg.Lease.IdleTTL, "idle ttl")
	v4 := fs.Int("ipv4-prefix-len", 24, "IPv4 lease prefix length, 24-32")
	v6 := fs.Int("ipv6-prefix-len", 128, "IPv6 lease prefix length, only 128")
	var allows multiFlag
	fs.Var(&allows, "allow", "允许来源 IP/CIDR，可重复")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	allowCIDRs, err := canonicalCIDRArgs([]string(allows)...)
	if err != nil {
		return err
	}
	cfg.Lease.Routes = upsertRoute(cfg.Lease.Routes, conf.Route{
		Label:         label,
		IdleTTL:       *idleTTL,
		IPv4PrefixLen: *v4,
		IPv6PrefixLen: *v6,
		IPAllowCIDRs:  allowCIDRs,
	})
	return saveConfig(cfg, "已写入临时放行路由: "+label)
}

func upsertRoute(routes []conf.Route, route conf.Route) []conf.Route {
	out := make([]conf.Route, 0, len(routes)+1)
	for _, r := range routes {
		if r.Label != route.Label {
			out = append(out, r)
		}
	}
	out = append(out, route)
	return out
}

func upsertTriggerRoute(routes []conf.TriggerRoute, route conf.TriggerRoute) []conf.TriggerRoute {
	out := make([]conf.TriggerRoute, 0, len(routes)+1)
	for _, r := range routes {
		if r.Token != route.Token {
			out = append(out, r)
		}
	}
	out = append(out, route)
	return out
}

func splitListen(raw string) (string, int, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, fmt.Errorf("无效监听地址 %q: %w", raw, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("无效监听端口: %s", portText)
	}
	return host, port, nil
}

func secretState(value string) string {
	if strings.TrimSpace(value) == "" {
		return "未设置"
	}
	return "已设置"
}

func routeV4Len(r conf.Route) int {
	if r.IPv4PrefixLen == 0 {
		return 24
	}
	return r.IPv4PrefixLen
}

func routeV6Len(r conf.Route) int {
	if r.IPv6PrefixLen == 0 {
		return 128
	}
	return r.IPv6PrefixLen
}

func routeV4LenFromValue(value int) int {
	if value == 0 {
		return 24
	}
	return value
}

func routeV6LenFromValue(value int) int {
	if value == 0 {
		return 128
	}
	return value
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func saveConfig(cfg conf.Config, msg string) error {
	if err := saveConfigValue(cfg); err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
