package nft

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	leaseIPv4MinPrefix = 24
	leaseIPv4MaxPrefix = 32
)

// ErrNftMissing 表示系统未安装 nft 命令。
var ErrNftMissing = errors.New("未找到 nft 命令；请安装 nftables")

// Available 报告系统是否可用 nft。
func Available() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// Check 用 `nft -c -f -` 校验规则文本语法，不实际应用。
func Check(ruleset string) error {
	return runNft(ruleset, "-c", "-f", "-")
}

// Apply 先 check 再 `nft -f -` 应用规则文本。
func Apply(ruleset string) error {
	if err := Check(ruleset); err != nil {
		return fmt.Errorf("规则校验失败: %w", err)
	}
	if err := DeleteTable(); err != nil {
		return err
	}
	return runNft(ruleset, "-f", "-")
}

// DeleteTable 删除 nwall 表（卸载/disable 用）；表不存在时忽略错误。
func DeleteTable() error {
	if !Available() {
		return ErrNftMissing
	}
	cmd := exec.Command("nft", "delete", "table", "inet", TableName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// 表不存在不是错误。
		if bytes.Contains(stderr.Bytes(), []byte("No such file")) {
			return nil
		}
		return fmt.Errorf("删除表失败: %w: %s", err, stderr.String())
	}
	return nil
}

// AddLeaseElement 写入带 timeout 的 lease 动态元素。
func AddLeaseElement(prefix netip.Prefix, timeout string) error {
	if !Available() {
		return ErrNftMissing
	}
	rule, err := leaseElementRule(prefix, timeout)
	if err != nil {
		return err
	}
	return runNft(rule, "-f", "-")
}

// AddLeasePrefix 写入带 timeout 的 lease 前缀。
func AddLeasePrefix(prefix netip.Prefix, timeout string) error {
	if !Available() {
		return ErrNftMissing
	}
	rule, err := leasePrefixRule(prefix, timeout)
	if err != nil {
		return err
	}
	return runNft(rule, "-f", "-")
}

func leaseElementRule(prefix netip.Prefix, timeout string) (string, error) {
	if prefix.Bits() != prefix.Addr().BitLen() {
		return "", fmt.Errorf("lease nft set 只支持主机地址，收到: %s", prefix)
	}
	if prefix.Addr().Is4() {
		return leasePrefixRule(prefix, timeout)
	}
	setName := "lease6"
	return fmt.Sprintf("add element inet %s %s { %s timeout %s }\n", TableName, setName, prefix.Addr().String(), timeout), nil
}

func leasePrefixRule(prefix netip.Prefix, timeout string) (string, error) {
	if !prefix.Addr().Is4() {
		return leaseElementRule(prefix, timeout)
	}
	if prefix.Bits() < leaseIPv4MinPrefix || prefix.Bits() > leaseIPv4MaxPrefix {
		return "", fmt.Errorf("IPv4 lease 前缀只支持 /24-/32，收到: %s", prefix)
	}
	prefix = prefix.Masked()
	return fmt.Sprintf("add element inet %s %s { %s timeout %s }\n", TableName, leaseIPv4SetName(prefix.Bits()), prefix.Addr().String(), timeout), nil
}

func leaseIPv4SetName(bits int) string {
	return fmt.Sprintf("lease4_%d", bits)
}

func leaseIPv4Mask(bits int) string {
	mask := uint32(0xffffffff) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}

// Snapshot 导出当前 nwall 表为可重放的规则文本；表不存在返回删除指令。
func Snapshot() (string, error) {
	if !Available() {
		return "", ErrNftMissing
	}
	cmd := exec.Command("nft", "list", "table", "inet", TableName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// 表当前不存在：回滚目标 = 删除表。
		if bytes.Contains(stderr.Bytes(), []byte("No such file")) {
			return "delete table inet " + TableName + "\n", nil
		}
		return "", fmt.Errorf("导出表失败: %w: %s", err, stderr.String())
	}
	// 在导出内容前加 flush，使其可直接重放覆盖当前状态。
	return stdout.String(), nil
}

// WriteSnapshot 把回滚快照原子写入 SnapshotPath。
func WriteSnapshot(snapshot string) error {
	if err := os.MkdirAll(filepath.Dir(SnapshotPath), 0o700); err != nil {
		return err
	}
	tmp := SnapshotPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(snapshot), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, SnapshotPath)
}

// RestoreSnapshot 从 SnapshotPath 恢复规则。
func RestoreSnapshot() error {
	data, err := os.ReadFile(SnapshotPath)
	if err != nil {
		return fmt.Errorf("读取快照失败: %w", err)
	}
	return ApplySnapshot(string(data))
}

// ApplySnapshot restores a previously captured nft table snapshot.
func ApplySnapshot(snapshot string) error {
	// 恢复前先删表，再重放快照，保证干净覆盖。
	_ = DeleteTable()
	return runNft(snapshot, "-f", "-")
}

// runNft 用 stdin 喂规则（避开超长 argv 限制），运行 `nft <args>`。
func runNft(stdin string, args ...string) error {
	if !Available() {
		return ErrNftMissing
	}
	cmd := exec.Command("nft", args...)
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}
