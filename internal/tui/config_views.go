package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
)

func (m model) updateProtect(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 5); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 5)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		m.cfg.Protect.Enabled = !m.cfg.Protect.Enabled
		if err := m.saveConfig("已切换防护开关"); err != nil {
			m.setError(err)
		}
	case 1:
		m.cfg.Protect.GuardAll = !m.cfg.Protect.GuardAll
		if err := m.saveConfig("已切换 guard_all"); err != nil {
			m.setError(err)
		}
	case 2:
		return m.prompt("默认回滚秒数", fmt.Sprint(m.cfg.Protect.RollbackTimeoutSec), "输入正整数秒数", func(m *model, raw string) error {
			value, err := parsePositiveInt(raw, "rollback_timeout_sec")
			if err != nil {
				return err
			}
			m.cfg.Protect.RollbackTimeoutSec = value
			return m.saveConfig("已更新回滚秒数")
		}), nil
	case 3:
		m.mode = viewOpenPorts
		m.cursor = 0
		m.status = ""
		m.err = ""
	case 4:
		m.mode = viewGuardedPorts
		m.cursor = 0
		m.status = ""
		m.err = ""
	}
	return m, nil
}

func (m model) viewProtect() string {
	rows := []row{
		{text: "防护: " + plainOnOff(m.cfg.Protect.Enabled), hint: "总开关"},
		{text: "保护所有端口: " + plainOnOff(m.cfg.Protect.GuardAll), hint: "关闭后只保护 guarded_ports"},
		{text: fmt.Sprintf("默认回滚: %d 秒", m.cfg.Protect.RollbackTimeoutSec), hint: "e 编辑"},
		{text: "公开端口: " + portRangesSummary(m.cfg.Protect.OpenPortRanges), hint: "本机填监听端口；DNAT 填公网原始入口端口"},
		{text: "受保护端口: " + portListSummary(m.cfg.Protect.GuardedPorts), hint: "guard_all=false 时只保护这些端口"},
	}
	return m.renderRows("防护", rows, "Enter/l 切换/进入 • e 编辑 • h/0/Esc 返回 • q 退出")
}

func (m model) updateOpenPorts(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Protect.OpenPortRanges)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewProtect
		m.cursor = 3
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增公开端口", "", "本机服务填监听端口；DNAT/forward 填公网原始入口端口；例如 40422,41423,40000-42000", func(m *model, raw string) error {
			ranges, err := parsePortRanges(raw)
			if err != nil {
				return err
			}
			next := append([]conf.PortRange(nil), m.cfg.Protect.OpenPortRanges...)
			next = append(next, ranges...)
			if err := validatePortRangesNoOverlap(next); err != nil {
				return err
			}
			m.cfg.Protect.OpenPortRanges = next
			m.cfg.Protect.OpenPorts = expandPortRangesForTUI(next)
			return m.saveConfig("已新增公开端口")
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		return m.prompt("删除公开端口", fmt.Sprint(m.cursor+1), "输入序号；支持 1 或 1,2 或 1-3", func(m *model, raw string) error {
			indexes, err := parseIndexSelection(raw, len(m.cfg.Protect.OpenPortRanges))
			if err != nil {
				return err
			}
			m.cfg.Protect.OpenPortRanges = removePortRangesByIndex(m.cfg.Protect.OpenPortRanges, indexes)
			m.cfg.Protect.OpenPorts = expandPortRangesForTUI(m.cfg.Protect.OpenPortRanges)
			if m.cursor >= len(m.cfg.Protect.OpenPortRanges) && m.cursor > 0 {
				m.cursor--
			}
			return m.saveConfig("已删除公开端口")
		}), nil
	case "c":
		m.cfg.Protect.OpenPortRanges = nil
		m.cfg.Protect.OpenPorts = nil
		if err := m.saveConfig("已清空公开端口"); err != nil {
			m.setError(err)
		}
		return m, nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewOpenPorts() string {
	rows := make([]row, 0, len(m.cfg.Protect.OpenPortRanges))
	for _, r := range m.cfg.Protect.OpenPortRanges {
		rows = append(rows, row{
			text:   formatPortRange(r),
			hint:   "公开放行",
			detail: "本机流量按 tcp/udp dport 放行；DNAT/forward 按公网原始入口端口放行。",
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无公开端口", hint: "按 a 新增"}}
	}
	return m.renderRows("防护 / 公开端口", rows, "a 新增 • d 按序号删除 • c 清空 • h/0/Esc 返回")
}

func (m model) updateGuardedPorts(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updatePortList(key, portListOptions{
		ports:       m.cfg.Protect.GuardedPorts,
		parent:      viewProtect,
		parentRow:   4,
		addTitle:    "新增受保护端口",
		delTitle:    "删除受保护端口",
		addStatus:   "已新增受保护端口",
		delStatus:   "已删除受保护端口",
		clearStatus: "已清空受保护端口",
		assign: func(m *model, ports []int) {
			m.cfg.Protect.GuardedPorts = ports
		},
	})
}

func (m model) viewGuardedPorts() string {
	return m.viewPortList("防护 / 受保护端口", m.cfg.Protect.GuardedPorts, "暂无受保护端口", "受白名单保护", "guard_all=false 时这些端口受保护。")
}

func (m model) updateIngress(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 6); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 6)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		m.cfg.Ingress.Enabled = !m.cfg.Ingress.Enabled
		if err := m.saveConfig("已切换入站白名单"); err != nil {
			m.setError(err)
		}
	case 1:
		m.cfg.Ingress.CNMode = nextCNMode(m.cfg.Ingress.CNMode)
		if m.cfg.Ingress.CNMode != "provinces" {
			m.cfg.Ingress.CNProvinces = nil
		}
		if err := m.saveConfig("已切换入站 CN 模式"); err != nil {
			m.setError(err)
		}
	case 2:
		m.mode = viewRegions
		m.regionBack = viewIngress
		m.cursor = 0
		m.status = ""
		m.err = ""
	case 3:
		m.mode = viewIngressCustomCIDRs
		m.cursor = 0
	case 4:
		m.mode = viewIngressPorts
		m.cursor = 0
	case 5:
		m.cfg.Ingress.CNProvinces = nil
		m.cfg.Ingress.CNCityCodes = nil
		if err := m.saveConfig("已清空入站省市选择"); err != nil {
			m.setError(err)
		}
	}
	return m, nil
}

func (m model) viewIngress() string {
	rows := []row{
		{text: "入站白名单: " + plainOnOff(m.cfg.Ingress.Enabled), hint: "总开关"},
		{text: "CN 模式: " + m.cfg.Ingress.CNMode, hint: "Enter 循环 off/all/provinces"},
		{text: "省市选择: " + m.regionSummary(), hint: "进入省/市树"},
		{text: "自定义 CIDR: " + countSummary(len(m.cfg.Ingress.CustomCIDRs)), hint: "加入入站来源白名单"},
		{text: "端口覆盖策略: " + countSummary(len(m.cfg.Ingress.PortPolicies)), hint: "为指定端口单独配置地区白名单"},
		{text: "清空省市选择", hint: "只清空全局省份/城市"},
	}
	return m.renderRows("入站", rows, "Enter 执行/进入 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateIngressCustomCIDRs(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.Ingress.CustomCIDRs,
		parent:      viewIngress,
		parentRow:   3,
		addTitle:    "新增入站自定义 CIDR",
		editTitle:   "修改入站自定义 CIDR",
		delTitle:    "删除入站自定义 CIDR",
		addStatus:   "已新增入站自定义 CIDR",
		editStatus:  "已修改入站自定义 CIDR",
		delStatus:   "已删除入站自定义 CIDR",
		clearStatus: "已清空入站自定义 CIDR",
		hint:        "自定义放行",
		assign: func(m *model, values []string) {
			m.cfg.Ingress.CustomCIDRs = values
		},
	})
}

func (m model) viewIngressCustomCIDRs() string {
	return m.viewCustomCIDRs("入站 / 自定义 CIDR", m.cfg.Ingress.CustomCIDRs)
}

func (m model) updateEgress(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 5); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 5)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		m.cfg.Egress.Enabled = !m.cfg.Egress.Enabled
		if err := m.saveConfig("已切换出站白名单"); err != nil {
			m.setError(err)
		}
	case 1:
		m.cfg.Egress.CNMode = nextCNMode(m.cfg.Egress.CNMode)
		if m.cfg.Egress.CNMode != "provinces" {
			m.cfg.Egress.CNProvinces = nil
		}
		if err := m.saveConfig("已切换出站 CN 模式"); err != nil {
			m.setError(err)
		}
	case 2:
		m.mode = viewEgressRegions
		m.cursor = 0
	case 3:
		m.mode = viewEgressCustomCIDRs
		m.cursor = 0
	case 4:
		m.cfg.Egress.CNProvinces = nil
		if err := m.saveConfig("已清空出站省份选择"); err != nil {
			m.setError(err)
		}
	}
	return m, nil
}

func (m model) viewEgress() string {
	rows := []row{
		{text: "出站白名单: " + plainOnOff(m.cfg.Egress.Enabled), hint: "总开关"},
		{text: "CN 模式: " + m.cfg.Egress.CNMode, hint: "Enter 循环 off/all/provinces"},
		{text: "省份选择: " + countSummary(len(m.cfg.Egress.CNProvinces)), hint: "进入省份树"},
		{text: "自定义 CIDR: " + countSummary(len(m.cfg.Egress.CustomCIDRs)), hint: "加入出站目标允许范围"},
		{text: "清空省份选择", hint: "只清空出站省份"},
	}
	return m.renderRows("出站", rows, "Enter 执行/进入 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateEgressCustomCIDRs(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.Egress.CustomCIDRs,
		parent:      viewEgress,
		parentRow:   3,
		addTitle:    "新增出站自定义 CIDR",
		editTitle:   "修改出站自定义 CIDR",
		delTitle:    "删除出站自定义 CIDR",
		addStatus:   "已新增出站自定义 CIDR",
		editStatus:  "已修改出站自定义 CIDR",
		delStatus:   "已删除出站自定义 CIDR",
		clearStatus: "已清空出站自定义 CIDR",
		hint:        "自定义放行",
		assign: func(m *model, values []string) {
			m.cfg.Egress.CustomCIDRs = values
		},
	})
}

func (m model) viewEgressCustomCIDRs() string {
	return m.viewCustomCIDRs("出站 / 自定义 CIDR", m.cfg.Egress.CustomCIDRs)
}

func (m model) viewCustomCIDRs(title string, cidrs []string) string {
	return m.viewCIDRList(title, cidrs, "暂无自定义 CIDR", "自定义放行", "")
}

type cidrListOptions struct {
	values      []string
	parent      viewMode
	parentRow   int
	addTitle    string
	editTitle   string
	delTitle    string
	addStatus   string
	editStatus  string
	delStatus   string
	clearStatus string
	hint        string
	detail      string
	assign      func(*model, []string)
}

func (m model) updateCIDRList(key tea.KeyMsg, opts cidrListOptions) (tea.Model, tea.Cmd) {
	total := len(opts.values)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = opts.parent
		m.cursor = opts.parentRow
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt(opts.addTitle, "", "输入 IP/CIDR；支持逗号分隔多个", func(m *model, raw string) error {
			cidrs, err := parseCIDRList(raw)
			if err != nil {
				return err
			}
			next := appendCIDRUnique(opts.values, cidrs...)
			opts.assign(m, next)
			return m.saveConfig(opts.addStatus)
		}), nil
	case "e", "enter", "l":
		if total == 0 {
			return m, nil
		}
		idx := m.cursor
		old := opts.values[idx]
		return m.prompt(opts.editTitle, old, "输入单个 IP/CIDR", func(m *model, raw string) error {
			cidr, err := parseSingleCIDR(raw)
			if err != nil {
				return err
			}
			next := append([]string(nil), opts.values...)
			if idx < 0 || idx >= len(next) {
				return fmt.Errorf("序号已失效")
			}
			next[idx] = cidr
			opts.assign(m, uniqueSorted(next))
			return m.saveConfig(opts.editStatus)
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		return m.prompt(opts.delTitle, fmt.Sprint(m.cursor+1), "输入序号；支持 1 或 1,2 或 1-3", func(m *model, raw string) error {
			indexes, err := parseIndexSelection(raw, len(opts.values))
			if err != nil {
				return err
			}
			next := removeStringsByIndex(opts.values, indexes)
			opts.assign(m, next)
			if m.cursor >= len(next) {
				m.cursor = len(next) - 1
			}
			if m.cursor < 0 {
				m.cursor = 0
			}
			return m.saveConfig(opts.delStatus)
		}), nil
	case "c":
		opts.assign(&m, nil)
		if err := m.saveConfig(opts.clearStatus); err != nil {
			m.setError(err)
		}
		return m, nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewCIDRList(title string, cidrs []string, emptyText, hint, detail string) string {
	rows := make([]row, 0, len(cidrs))
	for _, cidr := range cidrs {
		rows = append(rows, row{text: cidr, hint: hint, detail: detail})
	}
	if len(rows) == 0 {
		rows = []row{{text: emptyText, hint: "按 a 新增"}}
	}
	return m.renderRows(title, rows, "a 新增 • e/Enter 修改 • d 按序号删除 • c 清空 • h/0/Esc 返回")
}

func (m model) updateDPI(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 4); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 4)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		m.cfg.Protect.BlockHTTP = !m.cfg.Protect.BlockHTTP
		if err := m.saveConfig("已切换 HTTP 封锁"); err != nil {
			m.setError(err)
		}
	case 1:
		m.cfg.Protect.BlockTLS = !m.cfg.Protect.BlockTLS
		if err := m.saveConfig("已切换 TLS 封锁"); err != nil {
			m.setError(err)
		}
	case 2:
		m.cfg.Protect.BlockSOCKS = !m.cfg.Protect.BlockSOCKS
		if err := m.saveConfig("已切换 SOCKS 封锁"); err != nil {
			m.setError(err)
		}
	case 3:
		m.mode = viewDPISkipPorts
		m.cursor = 0
		m.status = ""
		m.err = ""
	}
	return m, nil
}

func (m model) viewDPI() string {
	rows := []row{
		{text: "HTTP 封锁: " + plainOnOff(m.cfg.Protect.BlockHTTP), hint: "Enter 切换"},
		{text: "TLS 封锁: " + plainOnOff(m.cfg.Protect.BlockTLS), hint: "Enter 切换"},
		{text: "SOCKS 封锁: " + plainOnOff(m.cfg.Protect.BlockSOCKS), hint: "Enter 切换"},
		{text: "跳过端口: " + portListSummary(m.cfg.Protect.ProtocolSkipPorts), hint: "这些端口跳过协议封锁"},
	}
	return m.renderRows("协议封锁", rows, "Enter 切换/编辑 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateDPISkipPorts(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updatePortList(key, portListOptions{
		ports:       m.cfg.Protect.ProtocolSkipPorts,
		parent:      viewDPI,
		parentRow:   3,
		addTitle:    "新增协议封锁跳过端口",
		delTitle:    "删除协议封锁跳过端口",
		addStatus:   "已新增协议封锁跳过端口",
		delStatus:   "已删除协议封锁跳过端口",
		clearStatus: "已清空协议封锁跳过端口",
		assign: func(m *model, ports []int) {
			m.cfg.Protect.ProtocolSkipPorts = ports
		},
	})
}

func (m model) viewDPISkipPorts() string {
	return m.viewPortList("协议封锁 / 跳过端口", m.cfg.Protect.ProtocolSkipPorts, "暂无跳过端口", "跳过 DPI", "这些端口不会进入 HTTP/TLS/SOCKS 协议封锁。")
}

type portListOptions struct {
	ports       []int
	parent      viewMode
	parentRow   int
	addTitle    string
	delTitle    string
	addStatus   string
	delStatus   string
	clearStatus string
	assign      func(*model, []int)
}

func (m model) updatePortList(key tea.KeyMsg, opts portListOptions) (tea.Model, tea.Cmd) {
	total := len(opts.ports)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = opts.parent
		m.cursor = opts.parentRow
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt(opts.addTitle, "", "逗号分隔端口或范围；例如 8443,40000-42000", func(m *model, raw string) error {
			ports, err := parsePortList(raw)
			if err != nil {
				return err
			}
			next := appendPortsUniqueSorted(opts.ports, ports...)
			opts.assign(m, next)
			return m.saveConfig(opts.addStatus)
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		return m.prompt(opts.delTitle, fmt.Sprint(m.cursor+1), "输入序号；支持 1 或 1,2 或 1-3", func(m *model, raw string) error {
			indexes, err := parseIndexSelection(raw, len(opts.ports))
			if err != nil {
				return err
			}
			next := removeIntsByIndex(opts.ports, indexes)
			opts.assign(m, next)
			if m.cursor >= len(next) {
				m.cursor = len(next) - 1
			}
			if m.cursor < 0 {
				m.cursor = 0
			}
			return m.saveConfig(opts.delStatus)
		}), nil
	case "c":
		opts.assign(&m, nil)
		if err := m.saveConfig(opts.clearStatus); err != nil {
			m.setError(err)
		}
		return m, nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewPortList(title string, ports []int, emptyText, hint, detail string) string {
	rows := make([]row, 0, len(ports))
	for _, port := range ports {
		rows = append(rows, row{
			text:   fmt.Sprint(port),
			hint:   hint,
			detail: detail,
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: emptyText, hint: "按 a 新增"}}
	}
	return m.renderRows(title, rows, "a 新增 • d 按序号删除 • c 清空 • h/0/Esc 返回")
}

func nextCNMode(mode string) string {
	switch mode {
	case "off", "":
		return "all"
	case "all":
		return "provinces"
	default:
		return "off"
	}
}

func plainOnOff(v bool) string {
	if v {
		return "开启"
	}
	return "关闭"
}

func countSummary(n int) string {
	if n == 0 {
		return "未设置"
	}
	return fmt.Sprintf("%d 项", n)
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

func clonePortPolicy(policy conf.PortPolicy) conf.PortPolicy {
	return conf.PortPolicy{
		ListenPort:  policy.ListenPort,
		CNMode:      policy.CNMode,
		CNProvinces: append([]string(nil), policy.CNProvinces...),
		CNCityCodes: append([]string(nil), policy.CNCityCodes...),
	}
}
