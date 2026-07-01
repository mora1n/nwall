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
	applyErr     error
	disableErr   error
	reloadErr    error
}

func (f *fakeActions) Apply(conf.Config, bool, int) error {
	f.applyCalls++
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
	return daemon.Status{OK: true, Components: map[string]daemon.ComponentStatus{}}, nil
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
	next, _ = got.updateConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Y'}})
	got = next.(model)
	if actions.applyCalls != 1 || got.err != "" || !strings.Contains(got.status, "已应用规则") {
		t.Fatalf("apply state mismatch calls=%d status=%q err=%q", actions.applyCalls, got.status, got.err)
	}
	got.cursor = 3
	next, _ = got.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(model)
	if actions.reloadCalls != 1 || got.err != "" || !strings.Contains(got.status, "daemon 已重载") {
		t.Fatalf("reload state mismatch calls=%d status=%q err=%q", actions.reloadCalls, got.status, got.err)
	}
}

func TestDisableActionUpdatesConfig(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus, cursor: 2}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	if actions.disableCalls != 1 || got.err != "" {
		t.Fatalf("disable state mismatch calls=%d status=%q err=%q", actions.disableCalls, got.status, got.err)
	}
	if store.cfg.Protect.Enabled {
		t.Fatal("disable should persist protect.enabled=false")
	}
}

func TestApplyActionSurfacesError(t *testing.T) {
	store := &fakeStore{cfg: conf.Default()}
	store.cfg.Protect.Enabled = true
	actions := &fakeActions{applyErr: errors.New("apply failed")}
	m := model{db: store, actions: actions, cfg: store.cfg, mode: viewStatus}
	next, _ := m.updateStatus(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(model)
	next, _ = got.updateConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Y'}})
	got = next.(model)
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

func TestRepeatScrollRequiresRepeatedKey(t *testing.T) {
	m := model{mode: viewHome}
	next, cmd, ok := m.moveCursor(tea.KeyMsg{Type: tea.KeyDown}, 7)
	got := next
	if !ok || cmd == nil || got.cursor != 1 {
		t.Fatalf("first down mismatch cursor=%d ok=%v cmd=%v", got.cursor, ok, cmd)
	}
	nextModel, _ := got.updateRepeat(repeatMsg{key: got.repeatKey, seq: got.repeatSeq})
	got = nextModel.(model)
	if got.cursor != 1 || got.repeatKey != "" {
		t.Fatalf("single key should not keep repeating cursor=%d repeat=%q", got.cursor, got.repeatKey)
	}
	next, _, _ = got.moveCursor(tea.KeyMsg{Type: tea.KeyDown}, 7)
	got = next
	next, _, _ = got.moveCursor(tea.KeyMsg{Type: tea.KeyDown}, 7)
	got = next
	nextModel, _ = got.updateRepeat(repeatMsg{key: got.repeatKey, seq: got.repeatSeq})
	got = nextModel.(model)
	if got.cursor != 4 {
		t.Fatalf("repeated key should continue scrolling, cursor=%d", got.cursor)
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
