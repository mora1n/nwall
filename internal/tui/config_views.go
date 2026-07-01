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
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 5); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 5)
	if key.String() == "e" {
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
		return m.prompt("公开端口", joinInts(m.cfg.Protect.OpenPorts), "逗号分隔端口；留空清空", func(m *model, raw string) error {
			ports, err := parsePortList(raw)
			if err != nil {
				return err
			}
			m.cfg.Protect.OpenPorts = ports
			return m.saveConfig("已更新公开端口")
		}), nil
	case 4:
		return m.prompt("受保护端口", joinInts(m.cfg.Protect.GuardedPorts), "逗号分隔端口；guard_all=false 时使用", func(m *model, raw string) error {
			ports, err := parsePortList(raw)
			if err != nil {
				return err
			}
			m.cfg.Protect.GuardedPorts = ports
			return m.saveConfig("已更新受保护端口")
		}), nil
	}
	return m, nil
}

func (m model) viewProtect() string {
	rows := []row{
		{text: "防护: " + plainOnOff(m.cfg.Protect.Enabled), hint: "总开关"},
		{text: "保护所有端口: " + plainOnOff(m.cfg.Protect.GuardAll), hint: "关闭后只保护 guarded_ports"},
		{text: fmt.Sprintf("默认回滚: %d 秒", m.cfg.Protect.RollbackTimeoutSec), hint: "e 编辑"},
		{text: "公开端口: " + joinInts(m.cfg.Protect.OpenPorts), hint: "e 编辑；这些端口不受白名单限制"},
		{text: "受保护端口: " + joinInts(m.cfg.Protect.GuardedPorts), hint: "e 编辑；guard_all=false 时使用"},
	}
	return m.renderRows("防护", rows, "Enter 切换/编辑 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateIngress(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 6); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 6)
	if key.String() == "e" {
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
		return m.prompt("入站自定义 CIDR", strings.Join(m.cfg.Ingress.CustomCIDRs, ","), "逗号分隔 IP/CIDR；留空清空", func(m *model, raw string) error {
			cidrs, err := parseCIDRList(raw)
			if err != nil {
				return err
			}
			m.cfg.Ingress.CustomCIDRs = cidrs
			return m.saveConfig("已更新入站自定义 CIDR")
		}), nil
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
		{text: "自定义 CIDR: " + countSummary(len(m.cfg.Ingress.CustomCIDRs)), hint: "e 编辑"},
		{text: "端口覆盖策略: " + countSummary(len(m.cfg.Ingress.PortPolicies)), hint: "进入列表"},
		{text: "清空省市选择", hint: "只清空全局省份/城市"},
	}
	return m.renderRows("入站", rows, "Enter 执行/进入 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateEgress(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 5); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 5)
	if key.String() == "e" {
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
		return m.prompt("出站自定义 CIDR", strings.Join(m.cfg.Egress.CustomCIDRs, ","), "逗号分隔 IP/CIDR；留空清空", func(m *model, raw string) error {
			cidrs, err := parseCIDRList(raw)
			if err != nil {
				return err
			}
			m.cfg.Egress.CustomCIDRs = cidrs
			return m.saveConfig("已更新出站自定义 CIDR")
		}), nil
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
		{text: "自定义 CIDR: " + countSummary(len(m.cfg.Egress.CustomCIDRs)), hint: "e 编辑"},
		{text: "清空省份选择", hint: "只清空出站省份"},
	}
	return m.renderRows("出站", rows, "Enter 执行/进入 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateDPI(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 4); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 4)
	if key.String() == "e" {
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
		return m.prompt("协议封锁跳过端口", joinInts(m.cfg.Protect.ProtocolSkipPorts), "逗号分隔端口；留空清空", func(m *model, raw string) error {
			ports, err := parsePortList(raw)
			if err != nil {
				return err
			}
			m.cfg.Protect.ProtocolSkipPorts = ports
			return m.saveConfig("已更新协议封锁跳过端口")
		}), nil
	}
	return m, nil
}

func (m model) viewDPI() string {
	rows := []row{
		{text: "HTTP 封锁: " + plainOnOff(m.cfg.Protect.BlockHTTP), hint: "Enter 切换"},
		{text: "TLS 封锁: " + plainOnOff(m.cfg.Protect.BlockTLS), hint: "Enter 切换"},
		{text: "SOCKS 封锁: " + plainOnOff(m.cfg.Protect.BlockSOCKS), hint: "Enter 切换"},
		{text: "跳过端口: " + joinInts(m.cfg.Protect.ProtocolSkipPorts), hint: "e 编辑"},
	}
	return m.renderRows("协议封锁", rows, "Enter 切换/编辑 • e 编辑 • 0/Esc 返回 • q 退出")
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
