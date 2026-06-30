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
