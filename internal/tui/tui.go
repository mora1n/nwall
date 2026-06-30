// Package tui implements nwall's interactive configuration UI.
package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/store"
)

type storeAPI interface {
	LoadConfig() (conf.Config, error)
	SaveConfig(conf.Config) error
}

type viewMode int

const (
	viewHome viewMode = iota
	viewRegions
	viewProvince
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("31"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	errStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	warnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
)

type model struct {
	db       storeAPI
	cfg      conf.Config
	geo      *geo.DB
	mode     viewMode
	cursor   int
	province string
	status   string
	err      string
}

// Run starts the interactive TUI.
func Run(db *store.DB) error {
	cfg, err := db.LoadConfig()
	if err != nil {
		return err
	}
	gdb, err := geo.Default()
	if err != nil {
		return err
	}
	p := tea.NewProgram(model{db: db, cfg: cfg, geo: gdb}, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch m.mode {
	case viewHome:
		return m.updateHome(key)
	case viewRegions:
		return m.updateRegions(key)
	case viewProvince:
		return m.updateProvince(key)
	default:
		return m, nil
	}
}

func (m model) updateHome(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 5 {
			m.cursor++
		}
	case "enter":
		switch m.cursor {
		case 0:
			m.cfg.Protect.Enabled = !m.cfg.Protect.Enabled
			m.save("已切换防护开关")
		case 1:
			m.cfg.Ingress.Enabled = !m.cfg.Ingress.Enabled
			m.save("已切换入站白名单")
		case 2:
			m.mode = viewRegions
			m.cursor = 0
			m.status = ""
		case 3:
			m.cfg.Egress.Enabled = !m.cfg.Egress.Enabled
			m.save("已切换出站白名单")
		case 4:
			m.cfg.Protect.BlockHTTP = !m.cfg.Protect.BlockHTTP
			m.save("已切换 HTTP 封锁")
		case 5:
			m.status = "租约和下行伪装高级参数请暂用 CLI 配置"
		}
	}
	return m, nil
}

func (m model) updateRegions(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	provs := m.geo.Provinces()
	switch key.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "0", "esc", "backspace":
		m.mode = viewHome
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(provs)-1 {
			m.cursor++
		}
	case "enter":
		if len(provs) > 0 {
			m.province = provs[m.cursor]
			m.mode = viewProvince
			m.cursor = 0
		}
	default:
		if idx, ok := numericChoice(key.String()); ok && idx >= 1 && idx <= len(provs) {
			m.province = provs[idx-1]
			m.mode = viewProvince
			m.cursor = 0
		}
	}
	return m, nil
}

func (m model) updateProvince(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	cities := m.geo.CitiesByProvince(m.province)
	maxCursor := len(cities)
	switch key.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "0", "esc", "backspace":
		m.mode = viewRegions
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < maxCursor {
			m.cursor++
		}
	case "enter":
		m = m.toggleProvinceItem(m.cursor, cities)
	default:
		if idx, ok := numericChoice(key.String()); ok {
			switch {
			case idx == 0:
				m.mode = viewRegions
				m.cursor = 0
			case idx == 1:
				m = m.toggleProvince()
			case idx >= 2 && idx <= len(cities)+1:
				m = m.toggleCity(cities[idx-2])
			}
		}
	}
	return m, nil
}

func (m model) toggleProvinceItem(cursor int, cities []geo.City) model {
	if cursor == 0 {
		return m.toggleProvince()
	}
	if cursor-1 >= 0 && cursor-1 < len(cities) {
		return m.toggleCity(cities[cursor-1])
	}
	return m
}

func (m model) toggleProvince() model {
	if contains(m.cfg.Ingress.CNProvinces, m.province) {
		m.cfg.Ingress.CNProvinces = remove(m.cfg.Ingress.CNProvinces, m.province)
		m.save("已取消省份: " + m.province)
		return m
	}
	m.cfg.Ingress.CNMode = "provinces"
	m.cfg.Ingress.CNProvinces = appendUnique(m.cfg.Ingress.CNProvinces, m.province)
	for _, city := range m.geo.CitiesByProvince(m.province) {
		m.cfg.Ingress.CNCityCodes = remove(m.cfg.Ingress.CNCityCodes, city.Code)
	}
	m.save("已选择省份: " + m.province)
	return m
}

func (m model) toggleCity(city geo.City) model {
	if contains(m.cfg.Ingress.CNProvinces, city.Province) {
		m.status = city.Name + " 已由 " + city.Province + " 覆盖"
		m.err = ""
		return m
	}
	if contains(m.cfg.Ingress.CNCityCodes, city.Code) {
		m.cfg.Ingress.CNCityCodes = remove(m.cfg.Ingress.CNCityCodes, city.Code)
		m.save("已取消城市: " + city.Province + "/" + city.Name)
		return m
	}
	m.cfg.Ingress.CNCityCodes = appendUnique(m.cfg.Ingress.CNCityCodes, city.Code)
	m.save("已选择城市: " + city.Province + "/" + city.Name)
	return m
}

func (m *model) save(msg string) {
	if err := m.db.SaveConfig(m.cfg); err != nil {
		m.err = err.Error()
		return
	}
	cfg, err := m.db.LoadConfig()
	if err != nil {
		m.err = err.Error()
		return
	}
	m.cfg = cfg
	m.status = msg
	m.err = ""
}

func (m model) View() string {
	switch m.mode {
	case viewRegions:
		return frame(m.viewRegions())
	case viewProvince:
		return frame(m.viewProvince())
	default:
		return frame(m.viewHome())
	}
}

func (m model) viewHome() string {
	rows := []string{
		fmt.Sprintf("防护: %s", onOff(m.cfg.Protect.Enabled)),
		fmt.Sprintf("入站白名单: %s", onOff(m.cfg.Ingress.Enabled)),
		fmt.Sprintf("地区白名单: %s", m.regionSummary()),
		fmt.Sprintf("出站白名单: %s", onOff(m.cfg.Egress.Enabled)),
		fmt.Sprintf("HTTP 封锁: %s", onOff(m.cfg.Protect.BlockHTTP)),
		"租约 / 下行伪装",
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("nwall 配置") + "\n\n")
	for i, row := range rows {
		line := fmt.Sprintf("%d. %s", i+1, row)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString(m.footer("↑/↓ 选择 • Enter 切换/进入 • q 退出"))
	return b.String()
}

func (m model) viewRegions() string {
	provs := m.geo.Provinces()
	var b strings.Builder
	b.WriteString(titleStyle.Render("地区白名单 / 选择省份") + "\n\n")
	b.WriteString("0. 返回\n")
	for i, p := range provs {
		mark := " "
		if contains(m.cfg.Ingress.CNProvinces, p) {
			mark = "✓"
		}
		line := fmt.Sprintf("%d. [%s] %s", i+1, mark, p)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString(m.footer("输入序号进入省份 • 0 返回 • q 退出"))
	return b.String()
}

func (m model) viewProvince() string {
	cities := m.geo.CitiesByProvince(m.province)
	var b strings.Builder
	b.WriteString(titleStyle.Render("地区白名单 / "+m.province) + "\n\n")
	provSelected := contains(m.cfg.Ingress.CNProvinces, m.province)
	provLine := fmt.Sprintf("1. [%s] 整个%s", mark(provSelected), m.province)
	if m.cursor == 0 {
		b.WriteString(selectedStyle.Render(provLine) + "\n")
	} else {
		b.WriteString(provLine + "\n")
	}
	for i, city := range cities {
		state := mark(contains(m.cfg.Ingress.CNCityCodes, city.Code))
		if provSelected {
			state = "覆盖"
		}
		line := fmt.Sprintf("%d. [%s] %s  %s", i+2, state, city.Name, city.Code)
		if i+1 == m.cursor {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString("\n0. 返回\n")
	if provSelected {
		b.WriteString(warnStyle.Render("已选择整个省份；该省城市由省份 IP 段覆盖，不单独保存。") + "\n")
	}
	b.WriteString(m.footer("1 选择/取消省份 • 2... 选择城市 • 0 返回"))
	return b.String()
}

func (m model) regionSummary() string {
	parts := []string{}
	if len(m.cfg.Ingress.CNProvinces) > 0 {
		parts = append(parts, fmt.Sprintf("%d 个省份", len(m.cfg.Ingress.CNProvinces)))
	}
	if len(m.cfg.Ingress.CNCityCodes) > 0 {
		parts = append(parts, fmt.Sprintf("%d 个城市", len(m.cfg.Ingress.CNCityCodes)))
	}
	if len(parts) == 0 {
		return "未选择"
	}
	return strings.Join(parts, "，")
}

func (m model) footer(help string) string {
	var b strings.Builder
	if m.err != "" {
		b.WriteString("\n" + errStyle.Render("错误: "+m.err) + "\n")
	} else if m.status != "" {
		b.WriteString("\n" + okStyle.Render(m.status) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render(help))
	return b.String()
}

func frame(s string) string {
	return lipgloss.NewStyle().PaddingLeft(2).PaddingRight(2).Render(s)
}

func onOff(v bool) string {
	if v {
		return labelStyle.Render("开启")
	}
	return helpStyle.Render("关闭")
}

func mark(v bool) string {
	if v {
		return "✓"
	}
	return " "
}

func numericChoice(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	return n, err == nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func remove(values []string, value string) []string {
	out := values[:0]
	for _, item := range values {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}
