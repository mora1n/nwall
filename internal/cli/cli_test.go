package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/store"
)

func TestIngressCityAndPortCommandsUpdateConfig(t *testing.T) {
	db := setupTestDB(t)

	code := firstCLICityCode(t)
	if err := Run([]string{"ingress", "city", "add", code}); err != nil {
		t.Fatalf("ingress city add: %v", err)
	}
	if err := Run([]string{"ingress", "port", "8443", "city", "add", code}); err != nil {
		t.Fatalf("ingress port city add: %v", err)
	}
	if err := Run([]string{"ingress", "port", "8443", "cn", "off"}); err != nil {
		t.Fatalf("ingress port cn off: %v", err)
	}

	got, err := db.LoadConfig()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Ingress.CNCityCodes) != 1 || got.Ingress.CNCityCodes[0] != code {
		t.Fatalf("全局 city code 未写入: %+v", got.Ingress.CNCityCodes)
	}
	if len(got.Ingress.PortPolicies) != 1 {
		t.Fatalf("端口策略数量不符: %+v", got.Ingress.PortPolicies)
	}
	policy := got.Ingress.PortPolicies[0]
	if policy.ListenPort != 8443 || policy.CNMode != "off" || len(policy.CNCityCodes) != 1 || policy.CNCityCodes[0] != code {
		t.Fatalf("端口策略内容不符: %+v", policy)
	}

	if err := Run([]string{"ingress", "port", "8443", "clear"}); err != nil {
		t.Fatalf("ingress port clear: %v", err)
	}
	got, err = db.LoadConfig()
	if err != nil {
		t.Fatalf("Load after clear: %v", err)
	}
	if len(got.Ingress.PortPolicies) != 0 {
		t.Fatalf("端口策略应已清除: %+v", got.Ingress.PortPolicies)
	}
}

func TestNewCommandsUpdateConfig(t *testing.T) {
	db := setupTestDB(t)

	if err := Run([]string{"egress", "enable"}); err != nil {
		t.Fatalf("egress enable: %v", err)
	}
	if err := Run([]string{"protect", "config", "set", "--clear-open-ports", "--open-port", "2222", "--open-port", "19082", "--guard-all", "true"}); err != nil {
		t.Fatalf("protect config set: %v", err)
	}
	if err := Run([]string{"egress", "custom", "add", "198.51.100.1"}); err != nil {
		t.Fatalf("egress custom add: %v", err)
	}
	if err := Run([]string{"ingress", "custom", "add", "203.0.113.9", "2001:db8::1"}); err != nil {
		t.Fatalf("ingress custom add: %v", err)
	}
	if err := Run([]string{"lease", "server", "set", "--lease-key", "secret", "--listen", "127.0.0.1:18090", "--trusted-relay", "198.51.100.7", "--trusted-relay", "198.51.100.7/32"}); err != nil {
		t.Fatalf("lease server set: %v", err)
	}
	if err := Run([]string{"lease", "route", "add", "office", "--idle-ttl", "5m", "--allow", "203.0.113.9"}); err != nil {
		t.Fatalf("lease route add: %v", err)
	}
	if err := Run([]string{"lease", "trigger", "set", "--listen", "127.0.0.1:19081", "--trusted-proxy", "127.0.0.1", "--trusted-proxy", "::1"}); err != nil {
		t.Fatalf("lease trigger set: %v", err)
	}
	if err := Run([]string{"lease", "trigger-route", "add", "test-token", "--label", "office", "--target", "198.51.100.7:19082", "--idle-ttl", "3d"}); err != nil {
		t.Fatalf("lease trigger-route add: %v", err)
	}
	if err := Run([]string{"downmask", "server", "set", "--tcp", "127.0.0.1:15301", "--token", "mask-token", "--max-rate", "1024"}); err != nil {
		t.Fatalf("downmask server set: %v", err)
	}
	if err := Run([]string{"dpi", "http", "on"}); err != nil {
		t.Fatalf("dpi http on: %v", err)
	}
	if err := Run([]string{"dpi", "skip-port", "add", "8443"}); err != nil {
		t.Fatalf("dpi skip-port add: %v", err)
	}

	got, err := db.LoadConfig()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.Egress.Enabled || len(got.Egress.CustomCIDRs) != 1 || got.Egress.CustomCIDRs[0] != "198.51.100.1/32" {
		t.Fatalf("egress 未写入: %+v", got.Egress)
	}
	wantIngressCIDRs := []string{"2001:db8::1/128", "203.0.113.9/32"}
	if !reflect.DeepEqual(got.Ingress.CustomCIDRs, wantIngressCIDRs) {
		t.Fatalf("ingress custom CIDR 未规范写入: got=%v want=%v", got.Ingress.CustomCIDRs, wantIngressCIDRs)
	}
	if len(got.Protect.OpenPorts) != 2 || got.Protect.OpenPorts[0] != 2222 || got.Protect.OpenPorts[1] != 19082 || !got.Protect.GuardAll {
		t.Fatalf("protect config 未写入: %+v", got.Protect)
	}
	if got.Lease.LeaseKey != "secret" || got.Lease.ListenPort != 18090 || len(got.Lease.TrustedRelayCIDRs) != 1 {
		t.Fatalf("lease config 未写入: %+v", got.Lease)
	}
	if got.Lease.TrustedRelayCIDRs[0] != "198.51.100.7/32" {
		t.Fatalf("trusted relay 应规范化裸 IP: %+v", got.Lease.TrustedRelayCIDRs)
	}
	if len(got.Lease.Routes) != 1 || got.Lease.Routes[0].Label != "office" {
		t.Fatalf("lease route 未写入: %+v", got.Lease.Routes)
	}
	if !reflect.DeepEqual(got.Lease.Routes[0].IPAllowCIDRs, []string{"203.0.113.9/32"}) {
		t.Fatalf("lease route allow 应规范化裸 IP: %+v", got.Lease.Routes[0].IPAllowCIDRs)
	}
	if got.LeaseTrigger.ListenPort != 19081 || len(got.LeaseTrigger.TrustedProxyCIDRs) != 2 {
		t.Fatalf("lease trigger config 未写入: %+v", got.LeaseTrigger)
	}
	if !reflect.DeepEqual(got.LeaseTrigger.TrustedProxyCIDRs, []string{"127.0.0.1/32", "::1/128"}) {
		t.Fatalf("trusted proxy 应规范化裸 IP: %+v", got.LeaseTrigger.TrustedProxyCIDRs)
	}
	if len(got.LeaseTrigger.Routes) != 1 || got.LeaseTrigger.Routes[0].Token != "test-token" || got.LeaseTrigger.Routes[0].Target != "198.51.100.7:19082" {
		t.Fatalf("lease trigger route 未写入: %+v", got.LeaseTrigger.Routes)
	}
	if got.Lease.Routes[0].IPv4PrefixLen != 24 || got.Lease.Routes[0].IPv6PrefixLen != 128 {
		t.Fatalf("lease route 默认前缀不符: %+v", got.Lease.Routes[0])
	}
	if !got.Protect.BlockHTTP || len(got.Protect.ProtocolSkipPorts) != 2 {
		t.Fatalf("dpi 未写入: %+v", got.Protect)
	}
	maskCfg, err := db.LoadDownmaskConfig()
	if err != nil {
		t.Fatalf("LoadDownmaskConfig: %v", err)
	}
	if maskCfg.TCPAddr != "127.0.0.1:15301" || maskCfg.Token != "mask-token" || maskCfg.MaxRate != 1024 {
		t.Fatalf("downmask config 未写入: %+v", maskCfg)
	}
}

func TestLeaseCIDRFlagsRejectInvalidIP(t *testing.T) {
	setupTestDB(t)
	if err := Run([]string{"lease", "server", "set", "--trusted-relay", "not-an-ip"}); err == nil {
		t.Fatal("invalid trusted relay should fail")
	}
	if err := Run([]string{"lease", "trigger", "set", "--trusted-proxy", "not-an-ip"}); err == nil {
		t.Fatal("invalid trusted proxy should fail")
	}
	if err := Run([]string{"lease", "route", "add", "office", "--allow", "not-an-ip"}); err == nil {
		t.Fatal("invalid route allow should fail")
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

func TestGeoExportCommand(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()
	if err := Run([]string{"geo", "export", "--mode", "off"}); err != nil {
		t.Fatalf("geo export: %v", err)
	}
	if got := stdout(); got != "" {
		t.Fatalf("off mode 应无输出，得 %q", got)
	}
}

func TestDefaultCommandRunsTUI(t *testing.T) {
	old := runTUICommand
	t.Cleanup(func() { runTUICommand = old })
	called := false
	runTUICommand = func(args []string) error {
		called = true
		if len(args) != 0 {
			t.Fatalf("default TUI args should be empty: %+v", args)
		}
		return nil
	}
	if err := Run(nil); err != nil {
		t.Fatalf("default run: %v", err)
	}
	if !called {
		t.Fatal("nwall 无参数时应默认执行 TUI")
	}
}

func TestProtectEnableParsesConfirmAndTimeout(t *testing.T) {
	db := setupTestDB(t)
	old := protectApplyCommand
	t.Cleanup(func() { protectApplyCommand = old })
	var gotCfg conf.Config
	var gotConfirm bool
	var gotTimeout int
	protectApplyCommand = func(cfg conf.Config, confirm bool, timeout int) error {
		gotCfg = cfg
		gotConfirm = confirm
		gotTimeout = timeout
		return nil
	}
	if err := Run([]string{"protect", "enable", "--confirm", "--timeout", "7"}); err != nil {
		t.Fatalf("protect enable: %v", err)
	}
	if !gotCfg.Protect.Enabled || !gotConfirm || gotTimeout != 7 {
		t.Fatalf("protect apply args 不符: enabled=%v confirm=%v timeout=%d", gotCfg.Protect.Enabled, gotConfirm, gotTimeout)
	}
	cfg, err := db.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Protect.Enabled {
		t.Fatal("protect enable 应写入 enabled=true")
	}
}

func TestHelpIncludesCommonExamples(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()
	if err := Run([]string{"-h"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	got := stdout()
	for _, want := range []string{
		"nwall                                                # 打开 TUI",
		"nwall protect config set --clear-open-ports --open-port 2222 --open-port 19082",
		"440100 440300 510100",
		"--allow 203.0.113.0/24",
		"添加临时放行路由",
		"--mask 24",
		"nwall lease trigger-route add <token>",
		"公网 token 触发器",
		"<downmask-key> 是下行伪装共享密钥",
		"daemon 通过 /run/nwall/nwall.sock 管理长期组件",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output missing %q:\n%s", want, got)
		}
	}
}

func TestUninstallDryRun(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()
	dir := t.TempDir()
	if err := Run([]string{"uninstall", "--dry-run", "--keep-config", "--prefix", filepath.Join(dir, "prefix"), "--state-dir", filepath.Join(dir, "state"), "--systemd-dir", filepath.Join(dir, "systemd")}); err != nil {
		t.Fatalf("uninstall dry-run: %v", err)
	}
	got := stdout()
	for _, want := range []string{"DRY-RUN: systemctl disable --now nwall.service", "DRY-RUN: nwall protect disable", "DRY-RUN: rm -f", "保留配置 DB", "保留状态目录"} {
		if !strings.Contains(got, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, got)
		}
	}
	for _, legacy := range legacyUnits {
		if strings.Contains(got, legacy) {
			t.Fatalf("uninstall dry-run should not touch legacy unit %q:\n%s", legacy, got)
		}
	}
}

func TestVerifySHA256RejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "nwall-linux-amd64-v0.1.0.tar.gz")
	sumFile := filepath.Join(dir, checksumsName)
	if err := os.WriteFile(archive, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := sha256.Sum256([]byte("other"))
	if err := os.WriteFile(sumFile, []byte(hex.EncodeToString(bad[:])+"  "+filepath.Base(archive)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(archive, sumFile); err == nil {
		t.Fatal("sha256 mismatch 应返回错误")
	}
}

func TestVerifySHA256UsesMatchingAsset(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "nwall-linux-amd64-v0.1.0.tar.gz")
	sumFile := filepath.Join(dir, checksumsName)
	payload := []byte("payload")
	if err := os.WriteFile(archive, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("other"))
	good := sha256.Sum256(payload)
	content := hex.EncodeToString(other[:]) + "  other.tar.gz\n" +
		hex.EncodeToString(good[:]) + "  " + filepath.Base(archive) + "\n"
	if err := os.WriteFile(sumFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(archive, sumFile); err != nil {
		t.Fatalf("应使用 SHA256SUMS 中匹配当前资产的条目: %v", err)
	}
}

func TestValidateReleasePayload(t *testing.T) {
	dir := t.TempDir()
	if err := validateReleasePayload(dir); err == nil {
		t.Fatal("缺少 nwall 时应返回错误")
	}
	bin := filepath.Join(dir, "nwall")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	systemdDir := filepath.Join(dir, "systemd")
	if err := os.MkdirAll(systemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, unit := range managedUnits {
		if err := os.WriteFile(filepath.Join(systemdDir, unit), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateReleasePayload(dir); err != nil {
		t.Fatalf("完整 release payload 应通过校验: %v", err)
	}
}

func firstCLICityCode(t *testing.T) string {
	t.Helper()
	db, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, city := range db.Cities() {
		prefixes, err := db.ExportCities([]string{city.Code})
		if err == nil && len(prefixes) > 0 {
			return city.Code
		}
	}
	t.Fatal("测试 geo 数据中没有可用城市 CIDR")
	return ""
}

func captureStdout(t *testing.T) (func() string, func()) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	return func() string {
			_ = w.Close()
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)
			return buf.String()
		}, func() {
			os.Stdout = old
			_ = r.Close()
		}
}
