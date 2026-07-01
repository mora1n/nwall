package tui

import (
	"errors"
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
	if got.err != "apply failed" {
		t.Fatalf("expected apply error, got status=%q err=%q", got.status, got.err)
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
