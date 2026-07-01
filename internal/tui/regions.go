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
	if m.backKey(key) {
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
	if moved, cmd, ok := m.moveCursor(key, len(provs)); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, len(provs))
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
	if m.backKey(key) {
		m.mode = viewRegions
		m.cursor = 0
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, total); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, total)
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
	return m.renderRowsWithIntro("地区白名单 / 选择省份", rows, "0. 返回", "输入序号后 Enter 进入省份 • 0 返回 • q 退出")
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
	out := m.renderRows("地区白名单 / "+m.province, rows, "输入序号后 Enter 选择 • 1 省份 • 2... 城市 • 0 返回")
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
	if m.backKey(key) {
		m.mode = viewEgress
		m.cursor = 2
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, len(provs)); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, len(provs))
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
	return m.renderRowsWithIntro("出站 / 选择省份", rows, "0. 返回", "输入序号后 Enter 选择/取消省份 • 0 返回 • q 退出")
}

func (m model) updateIngressPorts(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Ingress.PortPolicies)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewIngress
		m.cursor = 4
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增端口覆盖策略", "", "输入监听端口，例如 443", func(m *model, raw string) error {
			port, err := parsePort(raw)
			if err != nil {
				return err
			}
			m.portDraft = portPolicyDraft{active: true, policy: conf.PortPolicy{ListenPort: port, CNMode: "provinces"}}
			m.mode = viewPortPolicyMode
			m.cursor = 0
			return nil
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
	case "e", "enter", "l":
		if total == 0 {
			return m, nil
		}
		policy := clonePortPolicy(m.cfg.Ingress.PortPolicies[m.cursor])
		m.portDraft = portPolicyDraft{active: true, edit: true, old: policy.ListenPort, policy: policy}
		m.mode = viewPortPolicyMode
		m.cursor = cnModeCursor(policy.CNMode)
		m.status = ""
		m.err = ""
		return m, nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) updatePortPolicyMode(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewIngressPorts
		m.cursor = 0
		m.portDraft = portPolicyDraft{}
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, 3); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 3)
	if !ok {
		return m, nil
	}
	modes := []string{"off", "all", "provinces"}
	m.portDraft.policy.CNMode = modes[idx]
	if modes[idx] != "provinces" {
		m.portDraft.policy.CNProvinces = nil
		m.portDraft.policy.CNCityCodes = nil
		if err := m.savePortPolicyDraft(); err != nil {
			m.setError(err)
		}
		return m, nil
	}
	m.mode = viewPortPolicyRegions
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m, nil
}

func (m model) viewPortPolicyMode() string {
	rows := []row{
		{text: "off", hint: "该端口不使用地区白名单", detail: "Enter 保存；该端口关闭 CN 地区限制。"},
		{text: "all", hint: "允许 CN 全部地区", detail: "Enter 保存；该端口允许 CN 全量 IP 段。"},
		{text: "provinces", hint: "选择省份/城市", detail: "Enter 进入省市树；选择后保存该端口的覆盖策略。"},
	}
	return m.renderRows(fmt.Sprintf("端口覆盖 / %d / 模式", m.portDraft.policy.ListenPort), rows, "Enter 选择当前项 • 输入序号后 Enter • 0/Esc 返回")
}

func (m model) updatePortPolicyRegions(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	provs := m.geo.Provinces()
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewPortPolicyMode
		m.cursor = 2
		return m, nil
	}
	if key.String() == "s" {
		if err := m.savePortPolicyDraft(); err != nil {
			m.setError(err)
		}
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, len(provs)); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, len(provs))
	if !ok {
		return m, nil
	}
	m.province = provs[idx]
	m.mode = viewPortPolicyProvince
	m.cursor = 0
	return m, nil
}

func (m model) viewPortPolicyRegions() string {
	provs := m.geo.Provinces()
	rows := make([]row, 0, len(provs))
	for _, p := range provs {
		rows = append(rows, row{text: fmt.Sprintf("[%s] %s", mark(contains(m.portDraft.policy.CNProvinces, p)), p), detail: "Enter 进入该省城市；s 保存端口覆盖策略。"})
	}
	return m.renderRowsWithIntro(fmt.Sprintf("端口覆盖 / %d / 选择省份", m.portDraft.policy.ListenPort), rows, "s. 保存并返回", "输入序号后 Enter 进入省份 • s 保存 • 0 返回")
}

func (m model) updatePortPolicyProvince(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	cities := m.geo.CitiesByProvince(m.province)
	total := len(cities) + 1
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewPortPolicyRegions
		m.cursor = 0
		return m, nil
	}
	if key.String() == "s" {
		if err := m.savePortPolicyDraft(); err != nil {
			m.setError(err)
		}
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, total); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, total)
	if !ok {
		return m, nil
	}
	if idx == 0 {
		m = m.togglePortPolicyProvince()
		return m, nil
	}
	m = m.togglePortPolicyCity(cities[idx-1])
	return m, nil
}

func (m model) viewPortPolicyProvince() string {
	cities := m.geo.CitiesByProvince(m.province)
	rows := make([]row, 0, len(cities)+1)
	provSelected := contains(m.portDraft.policy.CNProvinces, m.province)
	rows = append(rows, row{text: fmt.Sprintf("[%s] 整个%s", mark(provSelected), m.province), detail: "Enter 选择/取消整个省份；省份会覆盖同省城市。"})
	for _, city := range cities {
		state := mark(contains(m.portDraft.policy.CNCityCodes, city.Code))
		if provSelected {
			state = "覆盖"
		}
		rows = append(rows, row{text: fmt.Sprintf("[%s] %s  %s", state, city.Name, city.Code), detail: "Enter 选择/取消城市；s 保存端口覆盖策略。"})
	}
	out := m.renderRows(fmt.Sprintf("端口覆盖 / %d / %s", m.portDraft.policy.ListenPort, m.province), rows, "输入序号后 Enter 选择 • 1 省份 • 2... 城市 • s 保存 • 0 返回")
	if provSelected {
		out += "\n" + warnStyle.Render("已选择整个省份；该省城市由省份 IP 段覆盖，不单独保存。")
	}
	return out
}

func (m model) togglePortPolicyProvince() model {
	policy := &m.portDraft.policy
	policy.CNMode = "provinces"
	if contains(policy.CNProvinces, m.province) {
		policy.CNProvinces = removeString(policy.CNProvinces, m.province)
		m.status = "已取消端口省份: " + m.province
		m.err = ""
		return m
	}
	policy.CNProvinces = appendUniqueString(policy.CNProvinces, m.province)
	for _, city := range m.geo.CitiesByProvince(m.province) {
		policy.CNCityCodes = removeString(policy.CNCityCodes, city.Code)
	}
	m.status = "已选择端口省份: " + m.province
	m.err = ""
	return m
}

func (m model) togglePortPolicyCity(city geo.City) model {
	policy := &m.portDraft.policy
	policy.CNMode = "provinces"
	if contains(policy.CNProvinces, city.Province) {
		m.status = city.Name + " 已由 " + city.Province + " 覆盖"
		m.err = ""
		return m
	}
	if contains(policy.CNCityCodes, city.Code) {
		policy.CNCityCodes = removeString(policy.CNCityCodes, city.Code)
		m.status = "已取消端口城市: " + city.Province + "/" + city.Name
		m.err = ""
		return m
	}
	policy.CNCityCodes = appendUniqueString(policy.CNCityCodes, city.Code)
	m.status = "已选择端口城市: " + city.Province + "/" + city.Name
	m.err = ""
	return m
}

func (m *model) savePortPolicyDraft() error {
	policy := clonePortPolicy(m.portDraft.policy)
	if policy.CNMode != "provinces" {
		policy.CNProvinces = nil
		policy.CNCityCodes = nil
	}
	if m.portDraft.edit {
		m.cfg.Ingress.PortPolicies = removePortPolicy(m.cfg.Ingress.PortPolicies, m.portDraft.old)
	}
	m.cfg.Ingress.PortPolicies = upsertPortPolicy(m.cfg.Ingress.PortPolicies, policy)
	m.portDraft = portPolicyDraft{}
	if err := m.saveConfig("已更新端口覆盖策略"); err != nil {
		return err
	}
	m.mode = viewIngressPorts
	m.cursor = 0
	return nil
}

func cnModeCursor(mode string) int {
	switch mode {
	case "off":
		return 0
	case "all":
		return 1
	default:
		return 2
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
