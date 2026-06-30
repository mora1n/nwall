package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mora1n/nwall/internal/conf"
)

func TestDefaultDBInitializesConfig(t *testing.T) {
	db := openTestDB(t)
	cfg, err := db.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Protect.OpenPorts[0] != 22 || cfg.Lease.ListenPort != 18080 || cfg.LeaseTrigger.ListenPort != 18081 {
		t.Fatalf("默认配置不符: %+v", cfg)
	}
}

func TestSaveConfigRoundTripModuleTables(t *testing.T) {
	db := openTestDB(t)
	cfg := conf.Default()
	cfg.Ingress.Enabled = true
	cfg.Ingress.CNMode = "provinces"
	cfg.Ingress.CNProvinces = []string{"广东省"}
	cfg.Ingress.CNCityCodes = []string{"440100", "510100"}
	cfg.Lease.LeaseKey = "secret"
	cfg.Lease.Routes = []conf.Route{{Label: "office", IdleTTL: "5m", IPv4PrefixLen: 24, IPv6PrefixLen: 128, IPAllowCIDRs: []string{"203.0.113.0/24"}}}
	cfg.LeaseTrigger.ListenHost = "127.0.0.1"
	cfg.LeaseTrigger.ListenPort = 19081
	cfg.LeaseTrigger.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}
	cfg.LeaseTrigger.Routes = []conf.TriggerRoute{{Token: "test-token", Label: "office", Target: "198.51.100.7:19082", IdleTTL: "3d", IPv4PrefixLen: 24, IPv6PrefixLen: 128}}
	if err := db.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := db.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(got.Ingress.CNCityCodes) != 1 || got.Ingress.CNCityCodes[0] != "510100" {
		t.Fatalf("广东省已选中时应删除同省城市 code: %+v", got.Ingress.CNCityCodes)
	}
	if len(got.Lease.Routes) != 1 || got.Lease.Routes[0].Label != "office" {
		t.Fatalf("lease routes round-trip 不符: %+v", got.Lease.Routes)
	}
	if got.LeaseTrigger.ListenPort != 19081 || len(got.LeaseTrigger.TrustedProxyCIDRs) != 2 {
		t.Fatalf("lease trigger config round-trip 不符: %+v", got.LeaseTrigger)
	}
	if len(got.LeaseTrigger.Routes) != 1 || got.LeaseTrigger.Routes[0].Token != "test-token" || got.LeaseTrigger.Routes[0].Target != "198.51.100.7:19082" {
		t.Fatalf("lease trigger route round-trip 不符: %+v", got.LeaseTrigger.Routes)
	}
}

func TestDefaultPortsAreNotReinsertedAfterSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nwall.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := db.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Protect.OpenPorts = []int{2222}
	cfg.Protect.ProtocolSkipPorts = []int{2222}
	if err := db.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Protect.OpenPorts) != 1 || got.Protect.OpenPorts[0] != 2222 {
		t.Fatalf("默认 open port 不应重新插入: %+v", got.Protect.OpenPorts)
	}
	if len(got.Protect.ProtocolSkipPorts) != 1 || got.Protect.ProtocolSkipPorts[0] != 2222 {
		t.Fatalf("默认 skip port 不应重新插入: %+v", got.Protect.ProtocolSkipPorts)
	}
}

func TestRuntimeStateAndNonce(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetRuntimeValue("snapshot", "table inet nwall {}"); err != nil {
		t.Fatal(err)
	}
	got, err := db.RuntimeValue("snapshot")
	if err != nil || got == "" {
		t.Fatalf("RuntimeValue=%q err=%v", got, err)
	}
	ok, err := db.RecordNonce("lease", "n1", nowPlusMinute())
	if err != nil || !ok {
		t.Fatalf("first nonce ok=%v err=%v", ok, err)
	}
	ok, err = db.RecordNonce("lease", "n1", nowPlusMinute())
	if err != nil || ok {
		t.Fatalf("replay nonce ok=%v err=%v", ok, err)
	}
}

func TestDownmaskSeedChunks(t *testing.T) {
	db := openTestDB(t)
	if err := db.GenerateDownmaskSeed(int64(SeedChunkSize + 17)); err != nil {
		t.Fatalf("GenerateDownmaskSeed: %v", err)
	}
	reader, err := db.NewSeedReader()
	if err != nil {
		t.Fatalf("NewSeedReader: %v", err)
	}
	buf := make([]byte, 64)
	if err := reader.ReadRandom(buf); err != nil {
		t.Fatalf("ReadRandom: %v", err)
	}
}

func TestDownmaskConfigStoresExternalSeedPath(t *testing.T) {
	db := openTestDB(t)
	cfg, err := db.LoadDownmaskConfig()
	if err != nil {
		t.Fatalf("LoadDownmaskConfig: %v", err)
	}
	if cfg.SeedPath != DefaultDownmaskSeedPath {
		t.Fatalf("default seed_path = %q, want %q", cfg.SeedPath, DefaultDownmaskSeedPath)
	}
	cfg.TCPAddr = "127.0.0.1:15301"
	cfg.SeedPath = filepath.Join(t.TempDir(), "seed.bin")
	if err := db.SaveDownmaskConfig(cfg); err != nil {
		t.Fatalf("SaveDownmaskConfig: %v", err)
	}
	got, err := db.LoadDownmaskConfig()
	if err != nil {
		t.Fatalf("LoadDownmaskConfig: %v", err)
	}
	if got.SeedPath != cfg.SeedPath || got.TCPAddr != cfg.TCPAddr {
		t.Fatalf("downmask config mismatch: %+v", got)
	}
}

func TestDownmaskDynamicTablesRoundTrip(t *testing.T) {
	db := openTestDB(t)
	policy := DownmaskPolicy{
		PullMode:         "ab",
		Iface:            "eth0",
		MinRatio:         1.25,
		MaxRatio:         1.75,
		TimeWindowStart:  "01:00",
		TimeWindowEnd:    "23:00",
		MaxJitterSeconds: 9,
		MinDeficitBytes:  1024,
		MaxBytesPerRun:   4096,
	}
	if err := db.SaveDownmaskPolicy(policy); err != nil {
		t.Fatalf("SaveDownmaskPolicy: %v", err)
	}
	gotPolicy, err := db.LoadDownmaskPolicy()
	if err != nil {
		t.Fatalf("LoadDownmaskPolicy: %v", err)
	}
	if gotPolicy != policy {
		t.Fatalf("policy mismatch: %+v", gotPolicy)
	}

	cfg := DownmaskABPullConfig{
		Protocol:           "udp",
		ProtocolMode:       "parallel",
		TCPEnabled:         true,
		UDPEnabled:         true,
		RemotePort:         15301,
		LocalIP:            "192.0.2.10",
		Token:              "test-token",
		SpeedLimit:         "4M",
		TimeoutSeconds:     300,
		ParallelLimit:      2,
		SpeedJitterPercent: 12,
		BytesJitterPercent: 18,
	}
	if err := db.SaveDownmaskABPullConfig(cfg); err != nil {
		t.Fatalf("SaveDownmaskABPullConfig: %v", err)
	}
	gotCfg, err := db.LoadDownmaskABPullConfig()
	if err != nil {
		t.Fatalf("LoadDownmaskABPullConfig: %v", err)
	}
	if gotCfg != cfg {
		t.Fatalf("ab config mismatch: %+v", gotCfg)
	}

	target := DownmaskABTarget{Host: "192.0.2.20", Port: 15301, Weight: 3, TCPEnabled: true}
	if err := db.UpsertDownmaskABTarget(target); err != nil {
		t.Fatalf("UpsertDownmaskABTarget: %v", err)
	}
	targets, err := db.LoadDownmaskABTargets()
	if err != nil {
		t.Fatalf("LoadDownmaskABTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].Host != target.Host || targets[0].Weight != 3 || targets[0].UDPEnabled {
		t.Fatalf("target mismatch: %+v", targets)
	}

	prev := 1.5
	state := DownmaskDayState{
		Date:                "2026-06-30",
		Iface:               "eth0",
		TargetRatio:         1.6,
		RXAccum:             100,
		TXAccum:             200,
		LastRXRaw:           1000,
		LastTXRaw:           2000,
		NextEligibleAt:      42,
		PreviousDate:        "2026-06-29",
		PreviousTargetRatio: &prev,
		GenerationSource:    "rollover_state",
		GeneratedAt:         "2026-06-30T00:00:00Z",
		LastAction:          "ab",
		LastActualBytes:     300,
		LastPlannedBytes:    400,
		LastError:           "",
		UpdatedAt:           "2026-06-30T00:01:00Z",
	}
	if err := db.SaveDownmaskDayState(state); err != nil {
		t.Fatalf("SaveDownmaskDayState: %v", err)
	}
	gotState, ok, err := db.LoadDownmaskDayState()
	if err != nil || !ok {
		t.Fatalf("LoadDownmaskDayState ok=%v err=%v", ok, err)
	}
	if gotState.PreviousTargetRatio == nil || *gotState.PreviousTargetRatio != prev || gotState.LastActualBytes != 300 {
		t.Fatalf("state mismatch: %+v", gotState)
	}

	history := DownmaskRatioHistory{
		Date:                state.Date,
		TargetRatio:         state.TargetRatio,
		PreviousDate:        state.PreviousDate,
		PreviousTargetRatio: state.PreviousTargetRatio,
		GenerationSource:    state.GenerationSource,
		GeneratedAt:         state.GeneratedAt,
	}
	if err := db.SaveDownmaskRatioHistory(history); err != nil {
		t.Fatalf("SaveDownmaskRatioHistory: %v", err)
	}
	gotHistory, ok, err := db.DownmaskRatioHistoryForDate(state.Date)
	if err != nil || !ok {
		t.Fatalf("DownmaskRatioHistoryForDate ok=%v err=%v", ok, err)
	}
	if gotHistory.TargetRatio != history.TargetRatio || gotHistory.PreviousTargetRatio == nil {
		t.Fatalf("history mismatch: %+v", gotHistory)
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "nwall.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func nowPlusMinute() time.Time {
	return time.Now().Add(time.Minute)
}
