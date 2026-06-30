// Package protect 编排 nwall 的应用/回滚生命周期（防锁死的定时确认）。
package protect

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/egress"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/ingress"
	"github.com/mora1n/nwall/internal/nft"
	"github.com/mora1n/nwall/internal/store"
)

const (
	runtimeSnapshotKey = "nft_snapshot"
	runtimeConfirmKey  = "apply_confirmed_at"
)

// BuildInput 把配置展开为 nft 渲染输入（含白名单来源前缀）。
func BuildInput(cfg conf.Config) (nft.Input, error) {
	in := nft.Input{
		Cfg:          cfg,
		LeaseTimeout: cfg.Lease.IdleTTL,
		EnableDPI:    cfg.Protect.BlockHTTP || cfg.Protect.BlockTLS || cfg.Protect.BlockSOCKS,
		NFQueueNum:   100,
	}
	if cfg.Ingress.Enabled {
		var db *geo.DB
		if ingressNeedsGeo(cfg.Ingress) {
			var err error
			db, err = geo.Default()
			if err != nil {
				return nft.Input{}, fmt.Errorf("加载 geo 库失败: %w", err)
			}
		}
		src, err := ingress.Build(cfg.Ingress, db)
		if err != nil {
			return nft.Input{}, err
		}
		in.WLSrcV4 = src.V4
		in.WLSrcV6 = src.V6
		for _, p := range src.Ports {
			in.PortPolicies = append(in.PortPolicies, nft.PortPolicyInput{
				ListenPort: p.ListenPort,
				WLSrcV4:    p.V4,
				WLSrcV6:    p.V6,
			})
		}
	}
	if cfg.Egress.Enabled {
		var db *geo.DB
		if cfg.Egress.CNMode != "" && cfg.Egress.CNMode != "off" {
			var err error
			db, err = geo.Default()
			if err != nil {
				return nft.Input{}, fmt.Errorf("加载 geo 库失败: %w", err)
			}
		}
		src, err := egress.Build(cfg.Egress, db)
		if err != nil {
			return nft.Input{}, err
		}
		in.EgressV4 = src.V4
		in.EgressV6 = src.V6
	}
	return in, nil
}

func ingressNeedsGeo(cfg conf.Ingress) bool {
	if (cfg.CNMode != "" && cfg.CNMode != "off") || len(cfg.CNCityCodes) > 0 {
		return true
	}
	for _, p := range cfg.PortPolicies {
		if (p.CNMode != "" && p.CNMode != "off") || len(p.CNCityCodes) > 0 {
			return true
		}
	}
	return false
}

// Apply 渲染并应用规则。confirm=true 直接生效（开机恢复/无人值守）；
// confirm=false 时启动 detached 倒计时，超时未确认自动回滚，防止锁死。
func Apply(cfg conf.Config, confirm bool, timeoutSec int) error {
	return applyWithStorePath(cfg, confirm, timeoutSec, storePath())
}

// ApplyWithDBPath renders and applies rules while storing runtime state in dbPath.
func ApplyWithDBPath(cfg conf.Config, confirm bool, timeoutSec int, dbPath string) error {
	if dbPath == "" {
		dbPath = storePath()
	}
	return applyWithStorePath(cfg, confirm, timeoutSec, dbPath)
}

func applyWithStorePath(cfg conf.Config, confirm bool, timeoutSec int, dbPath string) error {
	if !nft.Available() {
		return nft.ErrNftMissing
	}
	in, err := BuildInput(cfg)
	if err != nil {
		return err
	}
	ruleset := nft.Render(in)
	if err := nft.Check(ruleset); err != nil {
		return fmt.Errorf("规则校验失败: %w", err)
	}
	// 应用前先抓快照用于回滚。
	snapshot, err := nft.Snapshot()
	if err != nil {
		return fmt.Errorf("抓取回滚快照失败: %w", err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.SetRuntimeValue(runtimeSnapshotKey, snapshot); err != nil {
		return fmt.Errorf("写入回滚快照失败: %w", err)
	}
	if err := nft.Apply(ruleset); err != nil {
		return fmt.Errorf("应用规则失败: %w", err)
	}
	if confirm {
		clearConfirmSentinelAt(dbPath)
		return nil
	}
	if timeoutSec <= 0 {
		timeoutSec = cfg.Protect.RollbackTimeoutSec
	}
	return startRollbackTimer(timeoutSec)
}

// Confirm 写入确认哨兵，取消待定的回滚倒计时。
func Confirm() error {
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	return db.SetRuntimeValue(runtimeConfirmKey, time.Now().Format(time.RFC3339))
}

// Disable 删除 nwall 表，撤销全机防护。
func Disable() error {
	return nft.DeleteTable()
}

// startRollbackTimer fork 一个 detached 的 `nwall __rollback-timer` 子进程，
// 在 deadline 前轮询确认哨兵；未确认则恢复快照。
func startRollbackTimer(timeoutSec int) error {
	clearConfirmSentinel()
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位自身可执行文件失败: %w", err)
	}
	cmd := exec.Command(exe, "__rollback-timer", strconv.Itoa(timeoutSec))
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// detached：脱离父进程会话，确保父进程退出后倒计时仍在。
	cmd.SysProcAttr = detachedSysProcAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动回滚倒计时失败: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}

// RunRollbackTimer 是 `nwall __rollback-timer <sec>` 子命令的实现：
// 轮询确认哨兵，超时未确认则恢复快照。
func RunRollbackTimer(timeoutSec int) error {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		if confirmed() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if confirmed() {
		return nil
	}
	// 超时未确认：恢复快照，解除可能的锁死。
	db, err := store.Open(storePath())
	if err != nil {
		return err
	}
	defer db.Close()
	snapshot, err := db.RuntimeValue(runtimeSnapshotKey)
	if err != nil {
		return fmt.Errorf("读取回滚快照失败: %w", err)
	}
	_ = nft.DeleteTable()
	return nft.ApplySnapshot(snapshot)
}

func confirmed() bool {
	db, err := store.Open(storePath())
	if err != nil {
		return false
	}
	defer db.Close()
	_, err = db.RuntimeValue(runtimeConfirmKey)
	return err == nil
}

func clearConfirmSentinel() {
	clearConfirmSentinelAt(storePath())
}

func clearConfirmSentinelAt(path string) {
	db, err := store.Open(path)
	if err != nil {
		return
	}
	defer db.Close()
	_ = db.DeleteRuntimeValue(runtimeConfirmKey)
}

func storePath() string {
	if p := os.Getenv("NWALL_DB"); p != "" {
		return p
	}
	return store.DefaultPath
}
