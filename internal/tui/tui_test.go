package tui

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/daemon"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/store"
)

type fakeStore struct {
	cfg     conf.Config
	dmCfg   store.DownmaskConfig
	policy  store.DownmaskPolicy
	ab      store.DownmaskABPullConfig
	targets []store.DownmaskABTarget
}

func (f *fakeStore) LoadConfig() (conf.Config, error) { return f.cfg, nil }
func (f *fakeStore) SaveConfig(cfg conf.Config) error {
	f.cfg = cfg
	return nil
}
func (f *fakeStore) LoadDownmaskConfig() (store.DownmaskConfig, error) { return f.dmCfg, nil }
func (f *fakeStore) SaveDownmaskConfig(cfg store.DownmaskConfig) error {
	f.dmCfg = cfg
	return nil
}
func (f *fakeStore) LoadDownmaskPolicy() (store.DownmaskPolicy, error) { return f.policy, nil }
func (f *fakeStore) SaveDownmaskPolicy(policy store.DownmaskPolicy) error {
	f.policy = policy
	return nil
}
func (f *fakeStore) LoadDownmaskABPullConfig() (store.DownmaskABPullConfig, error) { return f.ab, nil }
func (f *fakeStore) SaveDownmaskABPullConfig(ab store.DownmaskABPullConfig) error {
	f.ab = ab
	return nil
}
func (f *fakeStore) LoadDownmaskABTargets() ([]store.DownmaskABTarget, error) {
	return append([]store.DownmaskABTarget(nil), f.targets...), nil
}
func (f *fakeStore) UpsertDownmaskABTarget(target store.DownmaskABTarget) error {
	for i, item := range f.targets {
		if item.Host == target.Host {
			f.targets[i] = target
			return nil
		}
	}
	f.targets = append(f.targets, target)
	return nil
}
func (f *fakeStore) DeleteDownmaskABTarget(host string) (bool, error) {
	for i, item := range f.targets {
		if item.Host == host {
			f.targets = append(f.targets[:i], f.targets[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeStore) LoadDownmaskStatus() (store.DownmaskStatus, bool, error) {
	return store.DownmaskStatus{}, false, nil
}
func (f *fakeStore) LoadDownmaskDayState() (store.DownmaskDayState, bool, error) {
	return store.DownmaskDayState{}, false, nil
}

type fakeActions struct {
	applyCalls   int
	disableCalls int
	reloadCalls  int
	applyCfg     conf.Config
	applyConfirm bool
	applyTimeout int
	applyErr     error
	disableErr   error
	reloadErr    error
	status       daemon.Status
	statusErr    error
}

func (f *fakeActions) Apply(cfg conf.Config, confirm bool, timeout int) error {
	f.applyCalls++
	f.applyCfg = cfg
	f.applyConfirm = confirm
	f.applyTimeout = timeout
	return f.applyErr
}
func (f *fakeActions) Disable() error {
	f.disableCalls++
	return f.disableErr
}
func (f *fakeActions) Reload() error {
	f.reloadCalls++
	return f.reloadErr
}
func (f *fakeActions) Status() (daemon.Status, error) {
	if f.status.Components != nil || f.status.StartedAt != "" || f.status.ReloadedAt != "" {
		return f.status, f.statusErr
	}
	return daemon.Status{OK: true, Components: map[string]daemon.ComponentStatus{
		"protect": {State: "running"},
	}}, f.statusErr
}

func runConfirmY(t *testing.T, m model) model {
	t.Helper()
	next, cmd := m.updateConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Y'}})
	pending := next.(model)
	if cmd == nil || !pending.busy || !strings.Contains(pending.status, "正在执行") {
		t.Fatalf("confirm should return busy model and command busy=%v status=%q cmd=%v", pending.busy, pending.status, cmd)
	}
	msg := cmd()
	next, cmd = pending.Update(msg)
	if cmd != nil {
		t.Fatalf("action done should not return follow-up cmd: %v", cmd)
	}
	got := next.(model)
	if got.busy {
		t.Fatal("action result should clear busy state")
	}
	return got
}

func TestProvinceSelectionCoversCity(t *testing.T) {
	gdb, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, geo: gdb, mode: viewProvince, province: "广东省"}
	m = m.toggleProvince()
	if !contains(m.cfg.Ingress.CNProvinces, "广东省") {
		t.Fatalf("province not selected: %+v", m.cfg.Ingress.CNProvinces)
	}
	cities := gdb.CitiesByProvince("广东省")
	if len(cities) == 0 {
		t.Fatal("广东省城市为空")
	}
	m = m.toggleCity(cities[0])
	if contains(m.cfg.Ingress.CNCityCodes, cities[0].Code) {
		t.Fatalf("省份已选中时不应保存城市 code: %+v", m.cfg.Ingress.CNCityCodes)
	}
}

func TestRegionNumberZeroReturnsHome(t *testing.T) {
	gdb, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, geo: gdb, mode: viewRegions}
	next, _ := m.updateRegions(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	got := next.(model)
	if got.mode != viewHome {
		t.Fatalf("0 should return home, got mode=%v", got.mode)
	}
}

func TestRegionMultiDigitNumberSelectsProvince(t *testing.T) {
	gdb, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	provs := gdb.Provinces()
	if len(provs) < 11 {
		t.Fatalf("省份数量不足以测试多位序号: %d", len(provs))
	}
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, geo: gdb, mode: viewRegions}
	next, _ := m.updateRegions(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	got := next.(model)
	if got.mode != viewRegions {
		t.Fatalf("输入首位 1 不应立即进入省份，mode=%v", got.mode)
	}
	next, _ = got.updateRegions(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	got = next.(model)
	if got.mode != viewProvince || got.province != provs[10] {
		t.Fatalf("输入 11 应进入第 11 个省份: mode=%v province=%q want=%q", got.mode, got.province, provs[10])
	}
}

func TestRepeatedDownMovesCursor(t *testing.T) {
	m := model{mode: viewHome}
	for range 3 {
		next, _ := m.updateHome(tea.KeyMsg{Type: tea.KeyDown})
		m = next.(model)
	}
	if m.cursor != 3 {
		t.Fatalf("重复 down 应连续移动 cursor，got=%d", m.cursor)
	}
}

func TestHomeIncludesExpectedGroups(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg}
	got := m.viewHome()
	for _, want := range []string{"状态 / 应用", "防护", "入站", "出站", "协议封锁", "TCP 租约", "下行伪装"} {
		if !strings.Contains(got, want) {
			t.Fatalf("home missing %q:\n%s", want, got)
		}
	}
}

func TestApplyAndReloadActionsSurfaceState(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewConfirm || actions.applyCalls != 0 {
		t.Fatalf("apply should wait for confirmation mode=%v calls=%d", got.mode, actions.applyCalls)
	}
	got = runConfirmY(t, got)
	if actions.applyCalls != 1 || actions.applyConfirm || actions.applyTimeout != 0 || got.err != "" || !strings.Contains(got.status, "已应用当前设置") {
		t.Fatalf("apply state mismatch calls=%d status=%q err=%q", actions.applyCalls, got.status, got.err)
	}
	if actions.reloadCalls != 0 {
		t.Fatalf("应用当前设置不应重载 daemon，reload calls=%d", actions.reloadCalls)
	}
	got.cursor = 1
	next, _ = got.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if actions.applyCalls != 2 || !actions.applyConfirm || actions.reloadCalls != 1 || got.err != "" || !strings.Contains(got.status, "已应用并确认当前设置") {
		t.Fatalf("apply+reload state mismatch applyCalls=%d confirm=%v reloadCalls=%d status=%q err=%q", actions.applyCalls, actions.applyConfirm, actions.reloadCalls, got.status, got.err)
	}
}

func TestStatusViewNoStandaloneReload(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewStatus}
	got := m.viewStatus()
	if strings.Contains(got, "4. 重载 daemon") {
		t.Fatalf("status view should merge daemon reload into apply confirm:\n%s", got)
	}
}

func TestApplyCurrentSettingsEnablesProtect(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = false
	actions := &fakeActions{}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	got = runConfirmY(t, got)
	if actions.applyCalls != 1 || !actions.applyCfg.Protect.Enabled {
		t.Fatalf("apply should receive enabled config calls=%d cfg=%+v", actions.applyCalls, actions.applyCfg.Protect)
	}
	if !store.cfg.Protect.Enabled || !got.cfg.Protect.Enabled {
		t.Fatalf("protect.enabled should be persisted and kept in model store=%v model=%v", store.cfg.Protect.Enabled, got.cfg.Protect.Enabled)
	}
	if got.err != "" || !strings.Contains(got.status, "已应用当前设置") {
		t.Fatalf("apply status mismatch status=%q err=%q", got.status, got.err)
	}
}

func TestApplyConfirmRejectsUnexpectedProtectStatus(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{status: daemon.Status{OK: true, Components: map[string]daemon.ComponentStatus{
		"protect": {State: "disabled", Message: "protect.enabled=false"},
	}}}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus, cursor: 1}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if actions.applyCalls != 1 || actions.reloadCalls != 1 {
		t.Fatalf("apply confirm should apply and reload calls=%d reloads=%d", actions.applyCalls, actions.reloadCalls)
	}
	if got.err == "" || !strings.Contains(got.err, "daemon protect 状态为 disabled") {
		t.Fatalf("expected protect state error, got status=%q err=%q", got.status, got.err)
	}
}

func TestDisableActionUpdatesConfig(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{status: daemon.Status{OK: true, Components: map[string]daemon.ComponentStatus{
		"protect": {State: "disabled"},
	}}}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus, cursor: 2}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if actions.disableCalls != 1 || actions.reloadCalls != 1 || got.err != "" {
		t.Fatalf("disable state mismatch disableCalls=%d reloadCalls=%d status=%q err=%q", actions.disableCalls, actions.reloadCalls, got.status, got.err)
	}
	if store.cfg.Protect.Enabled {
		t.Fatal("disable should persist protect.enabled=false")
	}
	if !got.hasDaemonStatus || got.daemonStatus.Components["protect"].State != "disabled" {
		t.Fatalf("disable should refresh daemon protect state: %+v", got.daemonStatus.Components["protect"])
	}
}

func TestApplyActionSurfacesError(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{applyErr: errors.New("apply failed")}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	got = runConfirmY(t, got)
	if got.err != "apply failed" {
		t.Fatalf("expected apply error, got status=%q err=%q", got.status, got.err)
	}
}

func TestApplyConfirmationCanCancel(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	actions := &fakeActions{}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	next, _ = got.updateConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	got = next.(model)
	if actions.applyCalls != 0 || got.mode != viewStatus || !strings.Contains(got.status, "已取消") {
		t.Fatalf("cancel mismatch calls=%d mode=%v status=%q", actions.applyCalls, got.mode, got.status)
	}
}

func TestRemoveStringDoesNotMutateInput(t *testing.T) {
	in := []string{"a", "b", "c"}
	original := append([]string(nil), in...)
	out := removeString(in, "b")
	if strings.Join(in, ",") != strings.Join(original, ",") {
		t.Fatalf("input mutated: got=%v want=%v", in, original)
	}
	if strings.Join(out, ",") != "a,c" {
		t.Fatalf("unexpected output: %v", out)
	}
}

func TestInputBackspaceRemovesOneRune(t *testing.T) {
	m := model{mode: viewInput, input: inputState{value: "广东"}}
	next, _ := m.updateInput(tea.KeyMsg{Type: tea.KeyBackspace})
	got := next.(model)
	if got.input.value != "广" {
		t.Fatalf("backspace should remove one rune, got %q", got.input.value)
	}
}

func TestParsePortListAcceptsRanges(t *testing.T) {
	got, err := parsePortList("40000-40002,60000-60001")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{40000, 40001, 40002, 60000, 60001}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("range parse mismatch: %v", got)
	}
}

func TestParsePortListDeduplicatesAndSortsRanges(t *testing.T) {
	got, err := parsePortList("22,40002,40000-40002,22")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 40000, 40001, 40002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("range dedupe mismatch: %v", got)
	}
}

func TestParsePortListAllowsEmptyInput(t *testing.T) {
	got, err := parsePortList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty input should clear list: %v", got)
	}
}

func TestParseByteRateAcceptsUnits(t *testing.T) {
	tests := []struct {
		raw  string
		want uint64
	}{
		{raw: "0", want: 0},
		{raw: "1048576", want: 1048576},
		{raw: "10MB", want: 10_000_000},
		{raw: "10MB/s", want: 10_000_000},
		{raw: "1GB", want: 1_000_000_000},
		{raw: "2kb/s", want: 2_000},
	}
	for _, tc := range tests {
		got, err := parseByteRate(tc.raw, "max_rate")
		if err != nil {
			t.Fatalf("parseByteRate(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("parseByteRate(%q)=%d want=%d", tc.raw, got, tc.want)
		}
	}
	for _, raw := range []string{"", "10Mbps", "-1MB", "abc"} {
		if _, err := parseByteRate(raw, "max_rate"); err == nil {
			t.Fatalf("parseByteRate(%q) should fail", raw)
		}
	}
}

func TestParseByteSizeAcceptsUnits(t *testing.T) {
	tests := []struct {
		raw  string
		want uint64
	}{
		{raw: "0", want: 0},
		{raw: "1048576", want: 1048576},
		{raw: "20MB", want: 20_000_000},
		{raw: "1.5GB", want: 1_500_000_000},
		{raw: "512KiB", want: 512 * 1024},
		{raw: "2M", want: 2 * 1024 * 1024},
	}
	for _, tc := range tests {
		got, err := parseByteSize(tc.raw, "bytes")
		if err != nil {
			t.Fatalf("parseByteSize(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("parseByteSize(%q)=%d want=%d", tc.raw, got, tc.want)
		}
	}
	for _, raw := range []string{"", "10MB/s", "-1MB", "abc"} {
		if _, err := parseByteSize(raw, "bytes"); err == nil {
			t.Fatalf("parseByteSize(%q) should fail", raw)
		}
	}
}

func TestParseCIDRListCanonicalizesSingleIPs(t *testing.T) {
	got, err := parseCIDRList("127.0.0.1, 2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1/32", "2001:db8::1/128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cidr canonicalization mismatch got=%v want=%v", got, want)
	}
}

func TestParsePortListRejectsInvalidRanges(t *testing.T) {
	for _, raw := range []string{"42000-40000", "0-10", "65535-65536", "abc-def", "1-2-3"} {
		if _, err := parsePortList(raw); err == nil {
			t.Fatalf("invalid range should fail: %q", raw)
		}
	}
}

func TestOpenPortListAddsAndDeletesRanges(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.OpenPortRanges = nil
	store.cfg.Protect.OpenPorts = nil
	m := model{db: store, cfg: store.cfg, mode: viewOpenPorts}
	next, _ := m.updateOpenPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	if got.input.value != "" {
		t.Fatalf("open port add prompt should not prefill default port, got %q", got.input.value)
	}
	got.input.value = "40000-42000,50000"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if len(store.cfg.Protect.OpenPortRanges) != 2 {
		t.Fatalf("ranges not saved: %+v", store.cfg.Protect.OpenPortRanges)
	}
	view := got.viewOpenPorts()
	if !strings.Contains(view, "40000-42000") || !strings.Contains(view, "50000") || strings.Contains(view, "40001") {
		t.Fatalf("open port view should preserve input groups:\n%s", view)
	}
	next, _ = got.updateOpenPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "1" {
		t.Fatalf("open port delete should default to current index, got %q", got.input.value)
	}
	got.input.value = "1"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if len(store.cfg.Protect.OpenPortRanges) != 1 || store.cfg.Protect.OpenPortRanges[0].Start != 50000 {
		t.Fatalf("range delete mismatch: %+v", store.cfg.Protect.OpenPortRanges)
	}
}

func TestOpenPortListRejectsOverlapsAndClears(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewOpenPorts}
	next, _ := m.updateOpenPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "22"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if got.err == "" {
		t.Fatal("overlapping open port should fail")
	}
	next, _ = m.updateOpenPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	got = next.(model)
	if len(store.cfg.Protect.OpenPortRanges) != 0 || len(store.cfg.Protect.OpenPorts) != 0 {
		t.Fatalf("clear mismatch ranges=%+v ports=%+v", store.cfg.Protect.OpenPortRanges, store.cfg.Protect.OpenPorts)
	}
}

func TestListEntryHintsDescribePurpose(t *testing.T) {
	m := model{cfg: conf.Default()}
	for name, view := range map[string]string{
		"protect":      m.viewProtect(),
		"ingress":      m.viewIngress(),
		"egress":       m.viewEgress(),
		"dpi":          m.viewDPI(),
		"lease":        m.viewLease(),
		"leaseTrigger": m.viewLeaseTrigger(),
	} {
		if strings.Contains(view, "进入列表") {
			t.Fatalf("%s should not use bare list hint:\n%s", name, view)
		}
	}
	ingress := m.viewIngress()
	for _, want := range []string{
		"加入入站来源白名单",
		"为指定端口单独配置地区白名单",
	} {
		if !strings.Contains(ingress, want) {
			t.Fatalf("ingress hint missing %q:\n%s", want, ingress)
		}
	}
	protect := m.viewProtect()
	for _, want := range []string{
		"DNAT",
		"公网原始入口端口",
	} {
		if !strings.Contains(protect, want) {
			t.Fatalf("protect hint missing %q:\n%s", want, protect)
		}
	}
}

func TestLeaseMenuPromotesTCPLeaseWorkflow(t *testing.T) {
	m := model{cfg: conf.Default()}
	view := m.viewLease()
	for _, want := range []string{
		"共享 key",
		"安装机接收租约监听",
		"临时放行路由",
		"允许发送租约到本机",
		"token 触发器监听",
		"token 路由",
		"反代真实 IP 来源",
		"高级参数",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("lease menu missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "公网 token 触发器 / 连接来源") {
		t.Fatalf("lease menu should not hide token routes under old combined entry:\n%s", view)
	}
}

func TestGuardedPortListAddsDeletesAndClears(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.GuardedPorts = nil
	m := model{db: store, cfg: store.cfg, mode: viewProtect, cursor: 4}
	next, _ := m.updateProtect(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewGuardedPorts {
		t.Fatalf("受保护端口应进入列表，mode=%v", got.mode)
	}
	assertPortListFlow(t, got, func(m model, key tea.KeyMsg) (tea.Model, tea.Cmd) {
		return m.updateGuardedPorts(key)
	}, func() []int {
		return store.cfg.Protect.GuardedPorts
	})
}

func TestDPISkipPortListAddsDeletesAndClears(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.ProtocolSkipPorts = nil
	m := model{db: store, cfg: store.cfg, mode: viewDPI, cursor: 3}
	next, _ := m.updateDPI(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewDPISkipPorts {
		t.Fatalf("跳过端口应进入列表，mode=%v", got.mode)
	}
	assertPortListFlow(t, got, func(m model, key tea.KeyMsg) (tea.Model, tea.Cmd) {
		return m.updateDPISkipPorts(key)
	}, func() []int {
		return store.cfg.Protect.ProtocolSkipPorts
	})
}

func assertPortListFlow(t *testing.T, m model, update func(model, tea.KeyMsg) (tea.Model, tea.Cmd), ports func() []int) {
	t.Helper()
	next, _ := update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	if got.input.value != "" {
		t.Fatalf("port add prompt should not prefill default port, got %q", got.input.value)
	}
	got.input.value = "8443,40000-40002,8443"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want := []int{8443, 40000, 40001, 40002}
	if !reflect.DeepEqual(ports(), want) {
		t.Fatalf("port add mismatch got=%v want=%v", ports(), want)
	}

	got.cursor = 2
	next, _ = update(got, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "3" {
		t.Fatalf("port delete should default to current index, got %q", got.input.value)
	}
	got.input.value = "1,3-4"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want = []int{40000}
	if !reflect.DeepEqual(ports(), want) {
		t.Fatalf("port delete mismatch got=%v want=%v", ports(), want)
	}
	if got.cursor != 0 {
		t.Fatalf("cursor should stay in range, got %d", got.cursor)
	}

	next, _ = update(got, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if len(ports()) != 0 {
		t.Fatalf("port clear mismatch: %v", ports())
	}
}

func TestCustomCIDRListAddsEditsAndBatchDeletes(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewIngressCustomCIDRs}
	next, _ := m.updateIngressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "127.0.0.1,198.51.100.0/24"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want := []string{"127.0.0.1/32", "198.51.100.0/24"}
	if !reflect.DeepEqual(store.cfg.Ingress.CustomCIDRs, want) {
		t.Fatalf("ingress cidr add mismatch got=%v want=%v", store.cfg.Ingress.CustomCIDRs, want)
	}

	got.cursor = 0
	next, _ = got.updateIngressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	got = next.(model)
	got.input.value = "2001:db8::1"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want = []string{"198.51.100.0/24", "2001:db8::1/128"}
	if !reflect.DeepEqual(store.cfg.Ingress.CustomCIDRs, want) {
		t.Fatalf("ingress cidr edit mismatch got=%v want=%v", store.cfg.Ingress.CustomCIDRs, want)
	}

	next, _ = got.updateIngressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "1" {
		t.Fatalf("ingress cidr delete should default to current index, got %q", got.input.value)
	}
	got.input.value = "1-2"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if len(store.cfg.Ingress.CustomCIDRs) != 0 {
		t.Fatalf("ingress cidr batch delete mismatch: %v", store.cfg.Ingress.CustomCIDRs)
	}
}

func TestEgressCustomCIDRListAddsAndClears(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewEgressCustomCIDRs}
	next, _ := m.updateEgressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "127.0.0.1 2001:db8::1"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want := []string{"127.0.0.1/32", "2001:db8::1/128"}
	if !reflect.DeepEqual(store.cfg.Egress.CustomCIDRs, want) {
		t.Fatalf("egress cidr add mismatch got=%v want=%v", store.cfg.Egress.CustomCIDRs, want)
	}
	got.cursor = 1
	next, _ = got.updateEgressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "2" {
		t.Fatalf("egress cidr delete should default to current index, got %q", got.input.value)
	}
	next, _ = got.updateEgressCustomCIDRs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if len(store.cfg.Egress.CustomCIDRs) != 0 {
		t.Fatalf("egress cidr clear mismatch: %v", store.cfg.Egress.CustomCIDRs)
	}
}

func TestLeaseTrustedRelayListAddsEditsAndBatchDeletes(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewLease, cursor: 3}
	next, _ := m.updateLease(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewLeaseTrustedRelays {
		t.Fatalf("allowed lease sender should enter list, mode=%v", got.mode)
	}

	next, _ = got.updateLeaseTrustedRelays(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got = next.(model)
	got.input.value = "198.176.52.125,2001:db8::1"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want := []string{"198.176.52.125/32", "2001:db8::1/128"}
	if !reflect.DeepEqual(store.cfg.Lease.TrustedRelayCIDRs, want) {
		t.Fatalf("trusted relay add mismatch got=%v want=%v", store.cfg.Lease.TrustedRelayCIDRs, want)
	}

	got.cursor = 0
	next, _ = got.updateLeaseTrustedRelays(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	got = next.(model)
	got.input.value = "198.51.100.0/24"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want = []string{"198.51.100.0/24", "2001:db8::1/128"}
	if !reflect.DeepEqual(store.cfg.Lease.TrustedRelayCIDRs, want) {
		t.Fatalf("trusted relay edit mismatch got=%v want=%v", store.cfg.Lease.TrustedRelayCIDRs, want)
	}

	next, _ = got.updateLeaseTrustedRelays(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "1" {
		t.Fatalf("trusted relay delete should default to current index, got %q", got.input.value)
	}
	got.input.value = "1-2"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if len(store.cfg.Lease.TrustedRelayCIDRs) != 0 {
		t.Fatalf("trusted relay batch delete mismatch: %v", store.cfg.Lease.TrustedRelayCIDRs)
	}
}

func TestLeaseTrustedProxyListAddsAndBatchDeletes(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewLease, cursor: 6}
	next, _ := m.updateLease(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewLeaseTrustedProxies {
		t.Fatalf("trusted proxy should enter list, mode=%v", got.mode)
	}

	next, _ = got.updateLeaseTrustedProxies(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got = next.(model)
	got.input.value = "127.0.0.1,::1"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	want := []string{"127.0.0.1/32", "::1/128"}
	if !reflect.DeepEqual(store.cfg.LeaseTrigger.TrustedProxyCIDRs, want) {
		t.Fatalf("trusted proxy add mismatch got=%v want=%v", store.cfg.LeaseTrigger.TrustedProxyCIDRs, want)
	}

	got.cursor = 1
	next, _ = got.updateLeaseTrustedProxies(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got = next.(model)
	if got.input.value != "2" {
		t.Fatalf("trusted proxy delete should default to current index, got %q", got.input.value)
	}
	got.input.value = "1,2"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if len(store.cfg.LeaseTrigger.TrustedProxyCIDRs) != 0 {
		t.Fatalf("trusted proxy batch delete mismatch: %v", store.cfg.LeaseTrigger.TrustedProxyCIDRs)
	}
}

func TestLeaseTriggerListenDeleteDisablesAndPreservesConfig(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.LeaseTrigger.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	store.cfg.LeaseTrigger.Routes = []conf.TriggerRoute{{Token: "tok", Label: "default", Target: "127.0.0.1:19082", IdleTTL: "3d", IPv4PrefixLen: 24, IPv6PrefixLen: 128}}
	m := model{db: store, cfg: store.cfg, mode: viewLease, cursor: 4}

	next, _ := m.updateLease(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	got := next.(model)
	if store.cfg.LeaseTrigger.Enabled || store.cfg.LeaseTrigger.ListenHost != "" || store.cfg.LeaseTrigger.ListenPort != 0 {
		t.Fatalf("trigger listen delete should disable and clear listen: %+v", store.cfg.LeaseTrigger)
	}
	if len(store.cfg.LeaseTrigger.Routes) != 1 || len(store.cfg.LeaseTrigger.TrustedProxyCIDRs) != 1 {
		t.Fatalf("trigger listen delete should preserve routes and proxies: %+v", store.cfg.LeaseTrigger)
	}
	if !strings.Contains(got.viewLease(), "token 触发器监听: -") {
		t.Fatalf("disabled trigger listen should render dash:\n%s", got.viewLease())
	}

	next, _ = got.updateLease(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if got.input.value != "" {
		t.Fatalf("disabled trigger listen prompt should start empty, got %q", got.input.value)
	}
	got.input.value = "127.0.0.1:19081"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	_ = next.(model)
	if !store.cfg.LeaseTrigger.Enabled || store.cfg.LeaseTrigger.ListenHost != "127.0.0.1" || store.cfg.LeaseTrigger.ListenPort != 19081 {
		t.Fatalf("editing listen should re-enable trigger: %+v", store.cfg.LeaseTrigger)
	}
}

func TestLeaseKeyPromptKeepsExistingValue(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Lease.LeaseKey = "secret"
	m := model{db: store, cfg: store.cfg, mode: viewLease, cursor: 0}
	next, _ := m.updateLease(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.input.value != "secret" {
		t.Fatalf("lease key prompt should keep current value, got %q", got.input.value)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if store.cfg.Lease.LeaseKey != "secret" {
		t.Fatalf("lease key should not be cleared, got %q", store.cfg.Lease.LeaseKey)
	}
}

func TestDownmaskKeyPromptKeepsExistingValue(t *testing.T) {
	store := &fakeStore{
		cfg:   conf.Default(),
		dmCfg: store.DownmaskConfig{Token: "mask-secret"},
		ab:    store.DownmaskABPullConfig{Token: "default-mask-secret"},
	}
	m := model{db: store, cfg: store.cfg, downmaskConfig: store.dmCfg, mode: viewDownmaskServer, cursor: 2}
	next, _ := m.updateDownmaskServer(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.input.value != "mask-secret" {
		t.Fatalf("downmask key prompt should keep current value, got %q", got.input.value)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if store.dmCfg.Token != "mask-secret" {
		t.Fatalf("downmask key should not be cleared, got %q", store.dmCfg.Token)
	}

	got.mode = viewDownmaskClient
	got.cursor = 11
	got.downmaskAB = store.ab
	next, _ = got.updateDownmaskClient(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if got.input.value != "default-mask-secret" {
		t.Fatalf("downmask default key prompt should keep current value, got %q", got.input.value)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if store.ab.Token != "default-mask-secret" {
		t.Fatalf("downmask default key should not be cleared, got %q", store.ab.Token)
	}
}

func TestLeaseRouteWizardAddsRoute(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewLeaseRoutes}
	next, _ := m.updateLeaseRoutes(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	for _, value := range []string{"default", "3d", "24", "128", "203.0.113.0/24"} {
		got.input.value = value
		next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
		got = next.(model)
	}
	if len(store.cfg.Lease.Routes) != 1 {
		t.Fatalf("route not saved: %+v", store.cfg.Lease.Routes)
	}
	route := store.cfg.Lease.Routes[0]
	if route.Label != "default" || route.IdleTTL != "3d" || route.IPv4PrefixLen != 24 || route.IPv6PrefixLen != 128 || !reflect.DeepEqual(route.IPAllowCIDRs, []string{"203.0.113.0/24"}) {
		t.Fatalf("route mismatch: %+v", route)
	}
}

func TestTriggerRouteWizardAddsRoute(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewLeaseTriggerRoutes}
	next, _ := m.updateLeaseTriggerRoutes(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "tok"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if !strings.Contains(got.input.help, "安装机上的临时放行路由名") || !strings.Contains(got.input.help, "本机没有临时放行路由") {
		t.Fatalf("trigger route label help should allow relay without local route:\n%s", got.input.help)
	}
	for _, value := range []string{"default", "127.0.0.1:19082", "3d", "24", "128"} {
		got.input.value = value
		next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
		got = next.(model)
	}
	if len(store.cfg.LeaseTrigger.Routes) != 1 {
		t.Fatalf("trigger route not saved: %+v", store.cfg.LeaseTrigger.Routes)
	}
	route := store.cfg.LeaseTrigger.Routes[0]
	if route.Token != "tok" || route.Label != "default" || route.Target != "127.0.0.1:19082" || route.IdleTTL != "3d" || route.IPv4PrefixLen != 24 || route.IPv6PrefixLen != 128 {
		t.Fatalf("trigger route mismatch: %+v", route)
	}
}

func TestTriggerRouteViewWarnsUntilListenConfigured(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Lease.LeaseKey = "secret"
	store.cfg.LeaseTrigger.Enabled = false
	store.cfg.LeaseTrigger.ListenHost = ""
	store.cfg.LeaseTrigger.ListenPort = 0
	m := model{db: store, cfg: store.cfg}
	view := m.viewLeaseTriggerRoutes()
	if !strings.Contains(view, "未设置 token 触发器监听，token 路由不会对外生效") {
		t.Fatalf("trigger route view should warn when listen is missing:\n%s", view)
	}

	store.cfg.LeaseTrigger.Enabled = true
	store.cfg.LeaseTrigger.ListenHost = "127.0.0.1"
	store.cfg.LeaseTrigger.ListenPort = 19081
	m.cfg = store.cfg
	view = m.viewLeaseTriggerRoutes()
	if strings.Contains(view, "未设置 token 触发器监听") {
		t.Fatalf("trigger route warning should disappear after listen configured:\n%s", view)
	}
}

func TestLeaseRouteWordingExplainsTemporaryAllow(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Lease.Routes = []conf.Route{{Label: "office", IdleTTL: "3d", IPv4PrefixLen: 24, IPv6PrefixLen: 128}}
	m := model{db: store, cfg: store.cfg}
	for name, view := range map[string]string{
		"lease":       m.viewLease(),
		"leaseRoutes": m.viewLeaseRoutes(),
	} {
		if !strings.Contains(view, "临时放行") {
			t.Fatalf("%s should explain temporary allow routes:\n%s", name, view)
		}
	}
}

func TestInputAcceptsSpaceKey(t *testing.T) {
	m := model{mode: viewInput, input: inputState{value: "1200"}}
	next, _ := m.updateInput(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	got := next.(model)
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	got = next.(model)
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	got = next.(model)
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("12")})
	got = next.(model)
	if got.input.value != "1200 2 12" {
		t.Fatalf("input value = %q, want %q", got.input.value, "1200 2 12")
	}
}

func TestIndexSelectionParsesListsAndRanges(t *testing.T) {
	got, err := parseIndexSelection("1,3-4", 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{0, 2, 3} {
		if _, ok := got[idx]; !ok {
			t.Fatalf("missing index %d in %+v", idx, got)
		}
	}
	if _, err := parseIndexSelection("0", 5); err == nil {
		t.Fatal("index 0 should fail")
	}
}

func TestVimNavigationKeys(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, mode: viewHome, cursor: 1}
	next, _ := m.updateHome(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got := next.(model)
	if got.mode != viewProtect {
		t.Fatalf("l should enter current item, mode=%v", got.mode)
	}
	next, _ = got.updateProtect(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	got = next.(model)
	if got.mode != viewHome {
		t.Fatalf("h should go back, mode=%v", got.mode)
	}
	input := model{mode: viewInput, input: inputState{value: ""}}
	next, _ = input.updateInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	got = next.(model)
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got = next.(model)
	if got.input.value != "hl" {
		t.Fatalf("h/l should remain text in input, got %q", got.input.value)
	}
}

func TestMoveCursorUsesOnlyKeyMessages(t *testing.T) {
	m := model{mode: viewHome}
	next, cmd, ok := m.moveCursor(tea.KeyMsg{Type: tea.KeyDown}, 7)
	got := next
	if !ok || cmd != nil || got.cursor != 1 {
		t.Fatalf("first down mismatch cursor=%d ok=%v cmd=%v", got.cursor, ok, cmd)
	}
	next, cmd, ok = got.moveCursor(tea.KeyMsg{Type: tea.KeyDown}, 7)
	got = next
	if !ok || cmd != nil || got.cursor != 2 {
		t.Fatalf("second down mismatch cursor=%d ok=%v cmd=%v", got.cursor, ok, cmd)
	}
	next, cmd, ok = got.moveCursor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}}, 7)
	got = next
	if !ok || cmd != nil || got.cursor != 3 {
		t.Fatalf("j down mismatch cursor=%d ok=%v cmd=%v", got.cursor, ok, cmd)
	}
	next, cmd, ok = got.moveCursor(tea.KeyMsg{Type: tea.KeyUp}, 7)
	got = next
	if !ok || cmd != nil || got.cursor != 2 {
		t.Fatalf("up mismatch cursor=%d ok=%v cmd=%v", got.cursor, ok, cmd)
	}
}

func TestParsePortPolicyAcceptsCityCodes(t *testing.T) {
	gdb, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	cities := gdb.CitiesByProvince("广东省")
	if len(cities) == 0 {
		t.Fatal("广东省城市为空")
	}
	policy, err := parsePortPolicy("8443 provinces 广东省 "+cities[0].Code, gdb)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ListenPort != 8443 || policy.CNMode != "provinces" {
		t.Fatalf("policy base mismatch: %+v", policy)
	}
	if len(policy.CNProvinces) != 1 || policy.CNProvinces[0] != "广东省" {
		t.Fatalf("province mismatch: %+v", policy.CNProvinces)
	}
	if len(policy.CNCityCodes) != 1 || policy.CNCityCodes[0] != cities[0].Code {
		t.Fatalf("city code mismatch: %+v", policy.CNCityCodes)
	}
}

func TestKeysAreVisibleInTUI(t *testing.T) {
	fs := &fakeStore{cfg: conf.Default()}
	fs.cfg.Lease.LeaseKey = "lease-secret"
	fs.cfg.LeaseTrigger.Routes = []conf.TriggerRoute{{Token: "trigger-token", Label: "office", Target: "198.51.100.7:19082"}}
	fs.dmCfg.Token = "mask-server-key"
	fs.ab.Token = "mask-client-key"
	fs.targets = []store.DownmaskABTarget{{Host: "198.51.100.9", Port: 15301, Weight: 1, TCPEnabled: true, Token: "target-key"}}
	m := model{db: fs, cfg: fs.cfg, downmaskConfig: fs.dmCfg, downmaskAB: fs.ab, downmaskTargets: fs.targets}
	if !strings.Contains(m.viewLease(), "lease-secret") {
		t.Fatal("lease key should be visible")
	}
	if !strings.Contains(m.viewLeaseTriggerRoutes(), "trigger-token") {
		t.Fatal("trigger token should be visible")
	}
	for _, want := range []string{"mask-server-key", "mask-client-key", "target-key"} {
		views := m.viewDownmask() + m.viewDownmaskServer() + m.viewDownmaskClient() + m.viewDownmaskTargets()
		if !strings.Contains(views, want) {
			t.Fatalf("downmask key should be visible: %q", want)
		}
	}
}

func TestLeaseKeyPromptGeneratesOnEmptyInput(t *testing.T) {
	fs := &fakeStore{cfg: conf.Default()}
	m := model{db: fs, cfg: fs.cfg, mode: viewLease, cursor: 0}
	next, _ := m.updateLease(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewInput || !strings.Contains(got.input.help, "nwall lease keygen") {
		t.Fatalf("lease key prompt mismatch mode=%v help=%q", got.mode, got.input.help)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if fs.cfg.Lease.LeaseKey == "" || got.cfg.Lease.LeaseKey != fs.cfg.Lease.LeaseKey {
		t.Fatalf("lease key not generated store=%q model=%q", fs.cfg.Lease.LeaseKey, got.cfg.Lease.LeaseKey)
	}
	if !strings.Contains(got.status, fs.cfg.Lease.LeaseKey) {
		t.Fatalf("generated lease key should be shown for copy, status=%q", got.status)
	}
}

func TestDownmaskKeysPromptGenerateOnEmptyInput(t *testing.T) {
	fs := &fakeStore{
		cfg:   conf.Default(),
		dmCfg: store.DownmaskConfig{SeedPath: store.DefaultDownmaskSeedPath, UDPPayloadBytes: 1200},
		ab: store.DownmaskABPullConfig{
			Protocol:       "tcp",
			ProtocolMode:   "single",
			RemotePort:     15301,
			TimeoutSeconds: 30,
			ParallelLimit:  1,
		},
	}
	m := model{db: fs, cfg: fs.cfg, downmaskConfig: fs.dmCfg, downmaskAB: fs.ab, mode: viewDownmaskServer, cursor: 2}
	next, _ := m.updateDownmaskServer(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if got.mode != viewInput || !strings.Contains(got.input.help, "openssl rand -hex 16") {
		t.Fatalf("downmask server key prompt mismatch mode=%v help=%q", got.mode, got.input.help)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if fs.dmCfg.Token == "" || got.downmaskConfig.Token != fs.dmCfg.Token {
		t.Fatalf("downmask server key not generated store=%q model=%q", fs.dmCfg.Token, got.downmaskConfig.Token)
	}
	if !strings.Contains(got.status, fs.dmCfg.Token) {
		t.Fatalf("generated downmask server key should be shown for copy, status=%q", got.status)
	}

	got.mode = viewDownmaskClient
	got.cursor = 11
	next, _ = got.updateDownmaskClient(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if got.mode != viewInput || !strings.Contains(got.input.help, "openssl rand -hex 16") {
		t.Fatalf("downmask client key prompt mismatch mode=%v help=%q", got.mode, got.input.help)
	}
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if fs.ab.Token == "" || got.downmaskAB.Token != fs.ab.Token {
		t.Fatalf("downmask default key not generated store=%q model=%q", fs.ab.Token, got.downmaskAB.Token)
	}
	if !strings.Contains(got.status, fs.ab.Token) {
		t.Fatalf("generated downmask default key should be shown for copy, status=%q", got.status)
	}
}

func TestLeaseAndDownmaskViewsExplainEditableFields(t *testing.T) {
	m := model{
		cfg: conf.Default(),
		downmaskConfig: store.DownmaskConfig{
			SeedPath:        store.DefaultDownmaskSeedPath,
			MaxRate:         10_000_000,
			UDPPayloadBytes: 1200,
		},
		downmaskAB: store.DownmaskABPullConfig{
			Protocol:      "udp",
			ProtocolMode:  "parallel",
			SpeedLimit:    "4M",
			ParallelLimit: 2,
		},
	}
	for name, view := range map[string]string{
		"lease":          m.viewLease(),
		"leaseRoutes":    m.viewLeaseTriggerRoutes(),
		"leaseAdvanced":  m.viewLeaseAdvanced(),
		"downmaskServer": m.viewDownmaskServer(),
		"downmaskClient": m.viewDownmaskClient(),
	} {
		for _, forbidden := range []string{"# e 编辑", "# e 设置新 key"} {
			if strings.Contains(view, forbidden) {
				t.Fatalf("%s should explain fields instead of %q:\n%s", name, forbidden, view)
			}
		}
	}
	combined := m.viewLease() + m.viewLeaseTriggerRoutes() + m.viewLeaseAdvanced() + m.viewDownmaskServer() + m.viewDownmaskClient()
	for _, want := range []string{
		"留空自动生成",
		"公网 token",
		"服务端发送限速",
		"UDP payload",
		"UDP 使用服务端 payload",
		"10MB/s",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("view explanation missing %q:\n%s", want, combined)
		}
	}
}

func TestPortPolicyWizardSavesOffMode(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, geo: mustGeo(t), mode: viewIngressPorts}
	next, _ := m.updateIngressPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "8443"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if got.mode != viewPortPolicyMode {
		t.Fatalf("输入端口后应进入模式选择，mode=%v", got.mode)
	}
	next, _ = got.updatePortPolicyMode(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	got = next.(model)
	if len(store.cfg.Ingress.PortPolicies) != 1 || store.cfg.Ingress.PortPolicies[0].ListenPort != 8443 || store.cfg.Ingress.PortPolicies[0].CNMode != "off" {
		t.Fatalf("off port policy not saved: %+v", store.cfg.Ingress.PortPolicies)
	}
}

func TestPortPolicyWizardSelectsProvince(t *testing.T) {
	gdb := mustGeo(t)
	store := &fakeStore{cfg: conf.Default()}
	m := model{db: store, cfg: store.cfg, geo: gdb, mode: viewIngressPorts}
	next, _ := m.updateIngressPorts(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	got := next.(model)
	got.input.value = "8443"
	next, _ = got.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	next, _ = got.updatePortPolicyMode(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	got = next.(model)
	got.province = "广东省"
	got.mode = viewPortPolicyProvince
	next, _ = got.updatePortPolicyProvince(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	got = next.(model)
	next, _ = got.updatePortPolicyProvince(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	next, _ = got.updatePortPolicyProvince(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	got = next.(model)
	if len(store.cfg.Ingress.PortPolicies) != 1 {
		t.Fatalf("policy missing: %+v", store.cfg.Ingress.PortPolicies)
	}
	policy := store.cfg.Ingress.PortPolicies[0]
	if policy.CNMode != "provinces" || len(policy.CNProvinces) != 1 || policy.CNProvinces[0] != "广东省" {
		t.Fatalf("province policy mismatch: %+v", policy)
	}
}

func mustGeo(t *testing.T) *geo.DB {
	t.Helper()
	gdb, err := geo.Default()
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}
