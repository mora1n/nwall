package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

type fakeStore struct {
	cfg conf.Config
}

func (f *fakeStore) LoadConfig() (conf.Config, error) { return f.cfg, nil }
func (f *fakeStore) SaveConfig(cfg conf.Config) error {
	f.cfg = cfg
	return nil
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
