package nft

// 运行时文件路径（最小化：仅回滚快照 + 确认哨兵）。
// 用 var 而非 const，便于测试重定向到临时目录。
var (
	// StateDir 是 nwall 的运行时状态目录。
	StateDir = "/var/lib/nwall"
	// SnapshotPath 是 apply 前的回滚快照。
	SnapshotPath = StateDir + "/snapshot.nft"
	// ConfirmSentinel 是 apply --confirm 写入的确认哨兵文件。
	ConfirmSentinel = "/run/nwall/apply.confirm"
)
