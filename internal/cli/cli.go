// Package cli 实现 nwall 的子命令分发与各命令处理。
package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/mask"
	"github.com/mora1n/nwall/internal/nft"
	"github.com/mora1n/nwall/internal/protect"
	"github.com/mora1n/nwall/internal/tui"
	appversion "github.com/mora1n/nwall/internal/version"
)

var runTUICommand = runTUI
var protectApplyCommand = protect.Apply

// Run 分发子命令。
func Run(args []string) error {
	if len(args) == 0 {
		return runTUICommand(nil)
	}
	switch args[0] {
	case "tui":
		return runTUICommand(args[1:])
	case "daemon":
		return runDaemon(args[1:])
	case "status":
		return runDaemonStatus(args[1:])
	case "reload":
		return runDaemonReload(args[1:])
	case "protect":
		return runProtect(args[1:])
	case "ingress":
		return runIngress(args[1:])
	case "egress":
		return runEgress(args[1:])
	case "lease":
		return runLease(args[1:])
	case "dpi":
		return runDPI(args[1:])
	case "downmask":
		return mask.Run(args[1:])
	case "geo":
		return runGeo(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "update":
		return runUpdate(args[1:])
	case "__rollback-timer":
		return runRollbackTimer(args[1:])
	case "version", "--version", "-v":
		fmt.Println(appversion.Version)
		return nil
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("未知子命令: %s", args[0])
	}
}

func runProtect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: nwall protect enable|disable|status|render|config|apply [--confirm] [--timeout N]")
	}
	switch args[0] {
	case "enable":
		fs := flag.NewFlagSet("protect enable", flag.ContinueOnError)
		confirm := fs.Bool("confirm", false, "直接生效，跳过回滚倒计时")
		timeout := fs.Int("timeout", 0, "回滚倒计时秒数，0=用配置默认")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return protectApply(true /*setEnabled*/, *confirm, *timeout)
	case "disable":
		return protectDisable()
	case "apply":
		fs := flag.NewFlagSet("apply", flag.ContinueOnError)
		confirm := fs.Bool("confirm", false, "直接生效，跳过回滚倒计时")
		timeout := fs.Int("timeout", 0, "回滚倒计时秒数，0=用配置默认")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return protectApply(false, *confirm, *timeout)
	case "status":
		return protectStatus()
	case "render":
		return protectRender()
	case "config":
		return protectConfig(args[1:])
	default:
		return fmt.Errorf("未知 protect 子命令: %s", args[0])
	}
}

func protectApply(setEnabled, confirm bool, timeout int) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if setEnabled {
		cfg.Protect.Enabled = true
		if err := saveConfigValue(cfg); err != nil {
			return err
		}
	}
	if !cfg.Protect.Enabled {
		return fmt.Errorf("protect.enabled=false；先执行 nwall protect enable")
	}
	if err := protectApplyCommand(cfg, confirm, timeout); err != nil {
		return err
	}
	if confirm {
		fmt.Println("已应用并确认。")
	} else {
		t := timeout
		if t <= 0 {
			t = cfg.Protect.RollbackTimeoutSec
		}
		fmt.Printf("已应用。请在 %d 秒内执行 `nwall protect apply --confirm` 确认，否则自动回滚。\n", t)
	}
	return nil
}

func protectDisable() error {
	cfg, err := loadConfig()
	if err == nil {
		cfg.Protect.Enabled = false
		_ = saveConfigValue(cfg)
	}
	if err := protect.Disable(); err != nil {
		return err
	}
	fmt.Println("已停用全机防护（已删除 nft 表）。")
	return nil
}

func protectStatus() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fmt.Printf("nft 可用: %v\n", nft.Available())
	fmt.Printf("protect.enabled: %v\n", cfg.Protect.Enabled)
	fmt.Printf("guard_all: %v\n", cfg.Protect.GuardAll)
	fmt.Printf("open_ports: %v\n", cfg.Protect.OpenPorts)
	if !cfg.Protect.GuardAll {
		fmt.Printf("guarded_ports: %v\n", cfg.Protect.GuardedPorts)
	}
	return nil
}

// protectRender 把当前配置渲染成 nft 规则文本打印到 stdout（调试/审阅用，不应用）。
func protectRender() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	in, err := protect.BuildInput(cfg)
	if err != nil {
		return err
	}
	fmt.Print(nft.Render(in))
	return nil
}

func protectConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("rollback_timeout_sec: %d\n", cfg.Protect.RollbackTimeoutSec)
		fmt.Printf("guard_all: %v\n", cfg.Protect.GuardAll)
		fmt.Printf("open_ports: %v\n", cfg.Protect.OpenPorts)
		fmt.Printf("guarded_ports: %v\n", cfg.Protect.GuardedPorts)
		fmt.Printf("protocol_skip_ports: %v\n", cfg.Protect.ProtocolSkipPorts)
		return nil
	}
	if args[0] != "set" {
		return fmt.Errorf("用法: nwall protect config show|set ...")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("protect config set", flag.ContinueOnError)
	rollbackTimeout := fs.Int("rollback-timeout-sec", 0, "默认回滚倒计时秒数")
	guardAll := fs.String("guard-all", "", "true|false")
	var openPorts intFlag
	var guardedPorts intFlag
	fs.Var(&openPorts, "open-port", "公开端口，可重复")
	fs.Var(&guardedPorts, "guarded-port", "受白名单保护端口，可重复")
	clearOpenPorts := fs.Bool("clear-open-ports", false, "清空公开端口")
	clearGuardedPorts := fs.Bool("clear-guarded-ports", false, "清空受保护端口")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *rollbackTimeout > 0 {
		cfg.Protect.RollbackTimeoutSec = *rollbackTimeout
	}
	if *guardAll != "" {
		value, err := parseBool(*guardAll)
		if err != nil {
			return err
		}
		cfg.Protect.GuardAll = value
	}
	if *clearOpenPorts {
		cfg.Protect.OpenPorts = nil
		cfg.Protect.OpenPortRanges = nil
	}
	if *clearGuardedPorts {
		cfg.Protect.GuardedPorts = nil
	}
	for _, port := range openPorts {
		cfg.Protect.OpenPorts = appendPortUnique(cfg.Protect.OpenPorts, port)
	}
	cfg.Protect.OpenPortRanges = portRangesFromPorts(cfg.Protect.OpenPorts)
	for _, port := range guardedPorts {
		cfg.Protect.GuardedPorts = appendPortUnique(cfg.Protect.GuardedPorts, port)
	}
	return saveConfig(cfg, "已更新 protect 配置")
}

func runTUI(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("用法: nwall tui")
	}
	db, err := openStore()
	if err != nil {
		return err
	}
	defer db.Close()
	return tui.Run(db)
}

func runRollbackTimer(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法: nwall __rollback-timer <秒>")
	}
	sec, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("无效秒数: %s", args[0])
	}
	return protect.RunRollbackTimer(sec)
}

func parseBool(raw string) (bool, error) {
	switch raw {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("必须是 true|false")
	}
}

type intFlag []int

func (f *intFlag) String() string {
	return fmt.Sprint([]int(*f))
}

func (f *intFlag) Set(raw string) error {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("无效端口: %s", raw)
	}
	*f = append(*f, value)
	return nil
}

func portRangesFromPorts(ports []int) []conf.PortRange {
	seen := map[int]struct{}{}
	values := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		values = append(values, port)
	}
	sort.Ints(values)
	if len(values) == 0 {
		return nil
	}
	out := make([]conf.PortRange, 0, len(values))
	start := values[0]
	prev := values[0]
	for _, port := range values[1:] {
		if port == prev+1 {
			prev = port
			continue
		}
		out = append(out, conf.PortRange{Start: start, End: prev})
		start = port
		prev = port
	}
	return append(out, conf.PortRange{Start: start, End: prev})
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, `nwall - nftables 白名单流量防护 + 下行伪装

用法:
  nwall                                                # 打开 TUI
  nwall tui                                            # 显式打开 TUI
  nwall daemon                                         # 启动本机 daemon，systemd 使用
  nwall status                                         # 查看 daemon 与组件状态
  nwall reload                                         # 重新加载 DB 配置并重启 daemon 组件
  nwall protect enable|disable|status|render           # 开关/查看/渲染防护规则
  nwall protect config set --clear-open-ports --open-port 2222 --open-port 19082 --guard-all true # 配置公开端口
  # DNAT 转发按公网原始端口配置，例如公网 41423 -> 后端:40422 时配置 41423
  nwall protect apply --confirm                        # 立即应用并确认规则
  nwall ingress enable|disable|status                  # 开关/查看入站白名单
  nwall ingress cn off|all|list|select <省份...>       # 配置全局入站中国省份白名单
  nwall ingress city add 440100 440300 510100          # 添加多个城市白名单；推荐用 TUI 按省/市选择
  nwall ingress custom add|del|list <IP/CIDR...>       # 管理自定义入站 CIDR
  nwall ingress port <port|ports> cn|city|status|clear ... # 管理端口覆盖策略，支持 443,8443,10000-10010
  nwall egress enable|disable|status                   # 开关/查看出站白名单
  nwall egress cn off|all|list|select <省份...>        # 配置出站中国省份白名单
  nwall egress custom add|del|list <IP/CIDR...>        # 管理自定义出站 CIDR
  nwall dpi http|tls|socks on|off                      # 开关协议封锁
  nwall dpi skip-port add|del|list <port>              # 管理协议封锁跳过端口
  nwall lease keygen                                   # 生成 TCP 租约共享 key
  nwall lease server set --lease-key "$(nwall lease keygen)" --listen 192.0.2.10:19082 --trusted-relay 198.51.100.0/24 # 配置 TCP 租约服务端
  nwall lease route add <label> --idle-ttl 3d --allow 203.0.113.0/24 # 添加临时放行路由，IPv4 默认放行来源 /24
  nwall lease send --target 192.0.2.10:19082 --route <label> --source-ip 203.0.113.9 --mask 24 # 手动发送 /24 租约
  nwall lease send --target 192.0.2.10:19082 --route <label> --source-ip 203.0.113.9 --mask 32 # 手动发送单 IP 租约
  nwall lease trigger set --listen 127.0.0.1:19081 --trusted-proxy 127.0.0.1/32 # 配置公网 token 触发器；--disable 停用
  nwall lease trigger-route add <token> --label <label> --target 192.0.2.10:19082 --idle-ttl 3d # 添加 token 到临时放行路由
  nwall downmask server set --tcp 0.0.0.0:15301 --udp 0.0.0.0:15301 --token <downmask-key> # 配置下行伪装服务端
  nwall downmask seed --size 268435456                 # 生成外部 seed 文件，DB 只保存路径
  nwall downmask client set --iface eth0 --min-ratio 1.5 --max-ratio 2 --remote-port 15301 --token <downmask-key> # 配置自动拉取
  nwall downmask target add 192.0.2.20 --weight 1      # 添加下行伪装服务端目标
  nwall downmask run                                   # 立即执行一次下行伪装缺口拉取
  nwall downmask status                                # 查看下行伪装策略与运行状态
  nwall geo export|refresh ...                         # 导出或刷新地理数据
  nwall update [--version vX.Y.Z]                      # 在线更新并自动回滚失败版本
  nwall uninstall [--keep-config|--purge-config]       # 卸载程序，可选择保留/删除 DB
  nwall version                                        # 输出版本

说明:
  <token> 是公网触发器 URL 令牌；<downmask-key> 是下行伪装共享密钥，二者互不通用。
  配置和运行状态保存在 /var/lib/nwall/nwall.db；daemon 通过 /run/nwall/nwall.sock 管理长期组件。`)
}
