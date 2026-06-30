// Package cli 实现 nwall 的子命令分发与各命令处理。
package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"

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
	case "dpi":
		return runDPI([]string{"run"})
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
	}
	if *clearGuardedPorts {
		cfg.Protect.GuardedPorts = nil
	}
	for _, port := range openPorts {
		cfg.Protect.OpenPorts = appendPortUnique(cfg.Protect.OpenPorts, port)
	}
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

func printUsage(w *os.File) {
	fmt.Fprintln(w, `nwall - nftables 白名单流量防护 + 下行伪装

用法:
  nwall                                                # 打开 TUI
  nwall tui
  nwall protect enable|disable|status|render
  nwall protect config set --clear-open-ports --open-port 2222 --open-port 19082 --guard-all true
  nwall protect apply --confirm
  nwall ingress enable|disable|status
  nwall ingress cn off|all|list|select <省份...>
  nwall ingress city add 440100 440300 510100             # 多个城市；推荐用 TUI 按省/市选择
  nwall ingress custom add|del|list <CIDR>
  nwall ingress port <port> cn|city|status|clear ...
  nwall egress enable|disable|status
  nwall egress cn off|all|list|select <省份...>
  nwall egress custom add|del|list <CIDR>
  nwall dpi http|tls|socks on|off
  nwall dpi skip-port add|del|list <port>
  nwall lease keygen
  nwall lease config set --lease-key "$(nwall lease keygen)" --listen 192.0.2.10:19082 --trusted-relay 198.51.100.0/24
  nwall lease route add <label> --idle-ttl 3d --allow 203.0.113.0/24
  nwall lease agent
  nwall lease send --target 192.0.2.10:19082 --route <label> --source-ip 203.0.113.9 --mask 24
  nwall lease send --target 192.0.2.10:19082 --route <label> --source-ip 203.0.113.9 --mask 32 # 单 IP
  nwall lease trigger-config set --listen 127.0.0.1:19081 --trusted-proxy 127.0.0.1/32
  nwall lease trigger-route add <token> --label <label> --target 192.0.2.10:19082 --idle-ttl 3d
  nwall lease trigger                                  # GET /<token>?mask=24 触发 TCP 租约
  nwall downmask config set --tcp-addr 0.0.0.0:15301 --udp-addr 0.0.0.0:15301 --token <downmask-token>
  nwall downmask seed --size 268435456
  nwall downmask serve                                  # 服务端发送下行伪装流量
  nwall downmask policy set --pull-mode ab --iface eth0 --min-ratio 1.5 --max-ratio 2
  nwall downmask ab-pull set --protocol-mode parallel --tcp-enabled true --udp-enabled true --remote-port 15301 --token <downmask-token>
  nwall downmask ab-pull targets add 192.0.2.20 --weight 1
  nwall downmask reconcile                              # 按 RX/TX 缺口拉取
  nwall downmask status
  nwall geo export|refresh ...
  nwall update [--version vX.Y.Z]
  nwall uninstall [--keep-config|--purge-config]
  nwall version

说明:
  <token> 是公网触发器 URL 令牌；<downmask-token> 是下行伪装共享令牌，二者互不通用。
  配置和运行状态保存在 /var/lib/nwall/nwall.db；执行 nwall protect apply --confirm 后才会应用规则。`)
}
