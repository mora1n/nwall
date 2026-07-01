package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

func (m model) updateRegions(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	provs := m.geo.Provinces()
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		if m.regionBack == 0 {
			m.mode = viewHome
			m.cursor = 0
		} else {
			m.mode = m.regionBack
			if m.regionBack == viewIngress {
				m.cursor = 2
			}
		}
		return m, nil
	}
	if moved, ok := m.moveCursor(key, len(provs)); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, len(provs))
	if !ok {
		return m, nil
	}
	m.province = provs[idx]
	m.mode = viewProvince
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m, nil
}

func (m model) updateProvince(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	cities := m.geo.CitiesByProvince(m.province)
	total := len(cities) + 1
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewRegions
		m.cursor = 0
		return m, nil
	}
	if moved, ok := m.moveCursor(key, total); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, total)
	if !ok {
		return m, nil
	}
	if idx == 0 {
		m = m.toggleProvince()
		return m, nil
	}
	m = m.toggleCity(cities[idx-1])
	return m, nil
}

func (m model) toggleProvince() model {
	if contains(m.cfg.Ingress.CNProvinces, m.province) {
		m.cfg.Ingress.CNProvinces = removeString(m.cfg.Ingress.CNProvinces, m.province)
		if err := m.saveConfig("已取消省份: " + m.province); err != nil {
			m.setError(err)
		}
		return m
	}
	m.cfg.Ingress.CNMode = "provinces"
	m.cfg.Ingress.CNProvinces = appendUniqueString(m.cfg.Ingress.CNProvinces, m.province)
	for _, city := range m.geo.CitiesByProvince(m.province) {
		m.cfg.Ingress.CNCityCodes = removeString(m.cfg.Ingress.CNCityCodes, city.Code)
	}
	if err := m.saveConfig("已选择省份: " + m.province); err != nil {
		m.setError(err)
	}
	return m
}

func (m model) toggleCity(city geo.City) model {
	if contains(m.cfg.Ingress.CNProvinces, city.Province) {
		m.status = city.Name + " 已由 " + city.Province + " 覆盖"
		m.err = ""
		return m
	}
	m.cfg.Ingress.CNMode = "provinces"
	if contains(m.cfg.Ingress.CNCityCodes, city.Code) {
		m.cfg.Ingress.CNCityCodes = removeString(m.cfg.Ingress.CNCityCodes, city.Code)
		if err := m.saveConfig("已取消城市: " + city.Province + "/" + city.Name); err != nil {
			m.setError(err)
		}
		return m
	}
	m.cfg.Ingress.CNCityCodes = appendUniqueString(m.cfg.Ingress.CNCityCodes, city.Code)
	if err := m.saveConfig("已选择城市: " + city.Province + "/" + city.Name); err != nil {
		m.setError(err)
	}
	return m
}

func (m model) viewRegions() string {
	provs := m.geo.Provinces()
	rows := make([]row, 0, len(provs))
	for _, p := range provs {
		rows = append(rows, row{text: fmt.Sprintf("[%s] %s", mark(contains(m.cfg.Ingress.CNProvinces, p)), p)})
	}
	return m.renderRowsWithIntro("地区白名单 / 选择省份", rows, "0. 返回", "输入序号进入省份 • 0 返回 • q 退出")
}

func (m model) viewProvince() string {
	cities := m.geo.CitiesByProvince(m.province)
	rows := make([]row, 0, len(cities)+1)
	provSelected := contains(m.cfg.Ingress.CNProvinces, m.province)
	rows = append(rows, row{text: fmt.Sprintf("[%s] 整个%s", mark(provSelected), m.province)})
	for _, city := range cities {
		state := mark(contains(m.cfg.Ingress.CNCityCodes, city.Code))
		if provSelected {
			state = "覆盖"
		}
		rows = append(rows, row{text: fmt.Sprintf("[%s] %s  %s", state, city.Name, city.Code)})
	}
	out := m.renderRows("地区白名单 / "+m.province, rows, "1 选择/取消省份 • 2... 选择城市 • 0 返回")
	if provSelected {
		out += "\n" + warnStyle.Render("已选择整个省份；该省城市由省份 IP 段覆盖，不单独保存。")
	}
	return out
}

func (m model) updateEgressRegions(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	provs := m.geo.Provinces()
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewEgress
		m.cursor = 2
		return m, nil
	}
	if moved, ok := m.moveCursor(key, len(provs)); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, len(provs))
	if !ok {
		return m, nil
	}
	province := provs[idx]
	m.cfg.Egress.CNMode = "provinces"
	if contains(m.cfg.Egress.CNProvinces, province) {
		m.cfg.Egress.CNProvinces = removeString(m.cfg.Egress.CNProvinces, province)
		if err := m.saveConfig("已取消出站省份: " + province); err != nil {
			m.setError(err)
		}
		return m, nil
	}
	m.cfg.Egress.CNProvinces = appendUniqueString(m.cfg.Egress.CNProvinces, province)
	if err := m.saveConfig("已选择出站省份: " + province); err != nil {
		m.setError(err)
	}
	return m, nil
}

func (m model) viewEgressRegions() string {
	provs := m.geo.Provinces()
	rows := make([]row, 0, len(provs))
	for _, p := range provs {
		rows = append(rows, row{text: fmt.Sprintf("[%s] %s", mark(contains(m.cfg.Egress.CNProvinces, p)), p)})
	}
	return m.renderRowsWithIntro("出站 / 选择省份", rows, "0. 返回", "输入序号选择/取消省份 • 0 返回 • q 退出")
}

func (m model) updateIngressPorts(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Ingress.PortPolicies)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewIngress
		m.cursor = 4
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增端口覆盖策略", "", "格式: <port> <off|all|provinces> [省份,省份] [城市code,城市code]", func(m *model, raw string) error {
			policy, err := parsePortPolicy(raw, m.geo)
			if err != nil {
				return err
			}
			m.cfg.Ingress.PortPolicies = upsertPortPolicy(m.cfg.Ingress.PortPolicies, policy)
			return m.saveConfig("已更新端口覆盖策略")
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		policy := m.cfg.Ingress.PortPolicies[m.cursor]
		m.cfg.Ingress.PortPolicies = removePortPolicy(m.cfg.Ingress.PortPolicies, policy.ListenPort)
		if m.cursor >= len(m.cfg.Ingress.PortPolicies) && m.cursor > 0 {
			m.cursor--
		}
		if err := m.saveConfig(fmt.Sprintf("已删除端口 %d 覆盖策略", policy.ListenPort)); err != nil {
			m.setError(err)
		}
		return m, nil
	case "e", "enter":
		if total == 0 {
			return m, nil
		}
		policy := clonePortPolicy(m.cfg.Ingress.PortPolicies[m.cursor])
		return m.prompt("编辑端口覆盖策略", formatPortPolicy(policy), "格式: <port> <off|all|provinces> [省份,省份] [城市code,城市code]", func(m *model, raw string) error {
			next, err := parsePortPolicy(raw, m.geo)
			if err != nil {
				return err
			}
			m.cfg.Ingress.PortPolicies = removePortPolicy(m.cfg.Ingress.PortPolicies, policy.ListenPort)
			m.cfg.Ingress.PortPolicies = upsertPortPolicy(m.cfg.Ingress.PortPolicies, next)
			return m.saveConfig("已更新端口覆盖策略")
		}), nil
	default:
		if moved, ok := m.moveCursor(key, total); ok {
			return moved, nil
		}
		return m, nil
	}
}

func (m model) viewIngressPorts() string {
	rows := make([]row, 0, len(m.cfg.Ingress.PortPolicies))
	for _, policy := range m.cfg.Ingress.PortPolicies {
		rows = append(rows, row{
			text: fmt.Sprintf("%d  %s", policy.ListenPort, policy.CNMode),
			hint: joinNonEmpty(strings.Join(policy.CNProvinces, ","), strings.Join(policy.CNCityCodes, ",")),
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无端口覆盖策略", hint: "按 a 新增"}}
	}
	return m.renderRows("入站 / 端口覆盖策略", rows, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
}

func upsertPortPolicy(policies []conf.PortPolicy, policy conf.PortPolicy) []conf.PortPolicy {
	out := make([]conf.PortPolicy, 0, len(policies)+1)
	for _, item := range policies {
		if item.ListenPort != policy.ListenPort {
			out = append(out, item)
		}
	}
	return append(out, policy)
}

func removePortPolicy(policies []conf.PortPolicy, port int) []conf.PortPolicy {
	out := make([]conf.PortPolicy, 0, len(policies))
	for _, item := range policies {
		if item.ListenPort != port {
			out = append(out, item)
		}
	}
	return out
}

func formatPortPolicy(policy conf.PortPolicy) string {
	parts := []string{fmt.Sprint(policy.ListenPort), policy.CNMode}
	if len(policy.CNProvinces) > 0 {
		parts = append(parts, strings.Join(policy.CNProvinces, ","))
	}
	if len(policy.CNCityCodes) > 0 {
		if len(policy.CNProvinces) == 0 {
			parts = append(parts, "-")
		}
		parts = append(parts, strings.Join(policy.CNCityCodes, ","))
	}
	return strings.Join(parts, " ")
}
