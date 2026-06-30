package protect

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mora1n/nwall/internal/nft"
	"github.com/mora1n/nwall/internal/store"
)

// 已确认时，倒计时应立即返回、不触发回滚（不依赖 nft）。
func TestRunRollbackTimerConfirmedReturnsEarly(t *testing.T) {
	setupTestDB(t)
	if err := Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	start := time.Now()
	if err := RunRollbackTimer(5); err != nil {
		t.Fatalf("RunRollbackTimer: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("已确认应立即返回，实际耗时 %v", elapsed)
	}
}

// 未确认且超时后应尝试恢复快照；nft 不可用时返回 ErrNftMissing，
// 但绝不会静默放过（验证回滚路径被触发）。
func TestRunRollbackTimerUnconfirmedTriggersRestore(t *testing.T) {
	db := setupTestDB(t)
	if err := db.SetRuntimeValue(runtimeSnapshotKey, "table inet nwall {}"); err != nil {
		t.Fatalf("SetRuntimeValue: %v", err)
	}
	err := RunRollbackTimer(0) // 立即超时
	if nft.Available() {
		return // 真机上不强求特定返回
	}
	if err == nil {
		t.Error("未确认超时且 nft 不可用时，应返回错误而非静默放过")
	}
}

func TestConfirmCreatesSentinel(t *testing.T) {
	setupTestDB(t)
	if confirmed() {
		t.Fatal("初始不应已确认")
	}
	if err := Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !confirmed() {
		t.Error("Confirm 后应已确认")
	}
}

func setupTestDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nwall.db")
	t.Setenv("NWALL_DB", path)
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
