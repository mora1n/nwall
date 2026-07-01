package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
)

func (m model) updateLease(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 7); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 7)
	if key.String() == "e" {
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		return m.prompt("TCP 租约监听地址", formatListen(m.cfg.Lease.ListenHost, m.cfg.Lease.ListenPort), "格式 HOST:PORT，例如 127.0.0.1:18080", func(m *model, raw string) error {
			host, port, err := splitHostPort(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.ListenHost = host
			m.cfg.Lease.ListenPort = port
			return m.saveConfig("已更新 TCP 租约监听")
		}), nil
	case 1:
		return m.prompt("TCP 租约共享 key", "", "输入新 key；不会回显当前值", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				return fmt.Errorf("lease key 不能为空")
			}
			m.cfg.Lease.LeaseKey = raw
			return m.saveConfig("已更新 TCP 租约 key")
		}), nil
	case 2:
		return m.prompt("默认租约时长", m.cfg.Lease.IdleTTL, "例如 10m、1h、3d", func(m *model, raw string) error {
			if err := validateTTL(raw); err != nil {
				return err
			}
			m.cfg.Lease.IdleTTL = raw
			return m.saveConfig("已更新默认租约时长")
		}), nil
	case 3:
		return m.prompt("签名时间窗秒数", fmt.Sprint(m.cfg.Lease.TSWindowSec), "输入正整数秒数", func(m *model, raw string) error {
			value, err := parsePositiveInt(raw, "ts_window_sec")
			if err != nil {
				return err
			}
			m.cfg.Lease.TSWindowSec = value
			return m.saveConfig("已更新签名时间窗")
		}), nil
	case 4:
		return m.prompt("可信 TCP relay CIDR", strings.Join(m.cfg.Lease.TrustedRelayCIDRs, ","), "逗号分隔 CIDR；留空清空", func(m *model, raw string) error {
			cidrs, err := parsePrefixList(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.TrustedRelayCIDRs = cidrs
			return m.saveConfig("已更新可信 relay")
		}), nil
	case 5:
		m.mode = viewLeaseRoutes
		m.cursor = 0
	case 6:
		m.mode = viewLeaseTrigger
		m.cursor = 0
	}
	return m, nil
}

func (m model) viewLease() string {
	rows := []row{
		{text: "监听: " + formatListen(m.cfg.Lease.ListenHost, m.cfg.Lease.ListenPort), hint: "e 编辑"},
		{text: "共享 key: " + secretState(m.cfg.Lease.LeaseKey), hint: "e 设置新 key"},
		{text: "默认租约时长: " + m.cfg.Lease.IdleTTL, hint: "e 编辑"},
		{text: fmt.Sprintf("签名时间窗: %d 秒", m.cfg.Lease.TSWindowSec), hint: "e 编辑"},
		{text: "可信 relay: " + countSummary(len(m.cfg.Lease.TrustedRelayCIDRs)), hint: "e 编辑"},
		{text: "租约路由: " + countSummary(len(m.cfg.Lease.Routes)), hint: "进入列表"},
		{text: "token 触发器", hint: fmt.Sprintf("%s routes=%d", formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), len(m.cfg.LeaseTrigger.Routes))},
	}
	return m.renderRows("TCP 租约", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Lease.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewLease
		m.cursor = 5
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增租约路由", "", "格式: <label> <ttl> <v4:24-32> <v6:128> [allow,allow]", func(m *model, raw string) error {
			route, err := parseLeaseRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.Routes = upsertRoute(m.cfg.Lease.Routes, route)
			return m.saveConfig("已更新租约路由")
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		label := m.cfg.Lease.Routes[m.cursor].Label
		m.cfg.Lease.Routes = removeRoute(m.cfg.Lease.Routes, label)
		if m.cursor >= len(m.cfg.Lease.Routes) && m.cursor > 0 {
			m.cursor--
		}
		if err := m.saveConfig("已删除租约路由: " + label); err != nil {
			m.setError(err)
		}
		return m, nil
	case "e", "enter":
		if total == 0 {
			return m, nil
		}
		route := m.cfg.Lease.Routes[m.cursor]
		return m.prompt("编辑租约路由", formatLeaseRoute(route), "格式: <label> <ttl> <v4:24-32> <v6:128> [allow,allow]", func(m *model, raw string) error {
			next, err := parseLeaseRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.Routes = removeRoute(m.cfg.Lease.Routes, route.Label)
			m.cfg.Lease.Routes = upsertRoute(m.cfg.Lease.Routes, next)
			return m.saveConfig("已更新租约路由")
		}), nil
	default:
		if moved, ok := m.moveCursor(key, total); ok {
			return moved, nil
		}
		return m, nil
	}
}

func (m model) viewLeaseRoutes() string {
	rows := make([]row, 0, len(m.cfg.Lease.Routes))
	for _, route := range m.cfg.Lease.Routes {
		rows = append(rows, row{
			text: fmt.Sprintf("%s  ttl=%s  v4/%d v6/%d", route.Label, valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), routeV4Len(route.IPv4PrefixLen), routeV6Len(route.IPv6PrefixLen)),
			hint: strings.Join(route.IPAllowCIDRs, ","),
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无租约路由", hint: "按 a 新增"}}
	}
	return m.renderRows("TCP 租约 / 路由", rows, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
}

func (m model) updateLeaseTrigger(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewLease
		m.cursor = 0
		return m, nil
	}
	if moved, ok := m.moveCursor(key, 3); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 3)
	if key.String() == "e" {
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		return m.prompt("公网 token 触发器监听", formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), "格式 HOST:PORT，例如 127.0.0.1:18081", func(m *model, raw string) error {
			host, port, err := splitHostPort(raw)
			if err != nil {
				return err
			}
			m.cfg.LeaseTrigger.ListenHost = host
			m.cfg.LeaseTrigger.ListenPort = port
			return m.saveConfig("已更新 token 触发器监听")
		}), nil
	case 1:
		return m.prompt("可信反代 CIDR", strings.Join(m.cfg.LeaseTrigger.TrustedProxyCIDRs, ","), "逗号分隔 CIDR；留空清空", func(m *model, raw string) error {
			cidrs, err := parsePrefixList(raw)
			if err != nil {
				return err
			}
			m.cfg.LeaseTrigger.TrustedProxyCIDRs = cidrs
			return m.saveConfig("已更新可信反代")
		}), nil
	case 2:
		m.mode = viewLeaseTriggerRoutes
		m.cursor = 0
	}
	return m, nil
}

func (m model) viewLeaseTrigger() string {
	rows := []row{
		{text: "监听: " + formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), hint: "e 编辑"},
		{text: "可信反代: " + countSummary(len(m.cfg.LeaseTrigger.TrustedProxyCIDRs)), hint: "e 编辑"},
		{text: "token 路由: " + countSummary(len(m.cfg.LeaseTrigger.Routes)), hint: "进入列表"},
	}
	return m.renderRows("TCP 租约 / token 触发器", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseTriggerRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.LeaseTrigger.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewLeaseTrigger
		m.cursor = 2
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增 token 路由", "", "格式: <token> <label> <target-host:port> <ttl> <v4:24-32> <v6:128>", func(m *model, raw string) error {
			route, err := parseTriggerRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.LeaseTrigger.Routes = upsertTriggerRoute(m.cfg.LeaseTrigger.Routes, route)
			return m.saveConfig("已更新 token 路由")
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		token := m.cfg.LeaseTrigger.Routes[m.cursor].Token
		m.cfg.LeaseTrigger.Routes = removeTriggerRoute(m.cfg.LeaseTrigger.Routes, token)
		if m.cursor >= len(m.cfg.LeaseTrigger.Routes) && m.cursor > 0 {
			m.cursor--
		}
		if err := m.saveConfig("已删除 token 路由"); err != nil {
			m.setError(err)
		}
		return m, nil
	case "e", "enter":
		if total == 0 {
			return m, nil
		}
		route := m.cfg.LeaseTrigger.Routes[m.cursor]
		return m.prompt("编辑 token 路由", formatTriggerRoute(route), "格式: <token> <label> <target-host:port> <ttl> <v4:24-32> <v6:128>", func(m *model, raw string) error {
			next, err := parseTriggerRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.LeaseTrigger.Routes = removeTriggerRoute(m.cfg.LeaseTrigger.Routes, route.Token)
			m.cfg.LeaseTrigger.Routes = upsertTriggerRoute(m.cfg.LeaseTrigger.Routes, next)
			return m.saveConfig("已更新 token 路由")
		}), nil
	default:
		if moved, ok := m.moveCursor(key, total); ok {
			return moved, nil
		}
		return m, nil
	}
}

func (m model) viewLeaseTriggerRoutes() string {
	rows := make([]row, 0, len(m.cfg.LeaseTrigger.Routes))
	for _, route := range m.cfg.LeaseTrigger.Routes {
		rows = append(rows, row{
			text: fmt.Sprintf("%s  %s -> %s", secretState(route.Token), route.Label, route.Target),
			hint: fmt.Sprintf("ttl=%s v4/%d v6/%d", valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), routeV4Len(route.IPv4PrefixLen), routeV6Len(route.IPv6PrefixLen)),
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无 token 路由", hint: "按 a 新增"}}
	}
	return m.renderRows("TCP 租约 / token 路由", rows, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
}

func upsertRoute(routes []conf.Route, route conf.Route) []conf.Route {
	out := make([]conf.Route, 0, len(routes)+1)
	for _, item := range routes {
		if item.Label != route.Label {
			out = append(out, item)
		}
	}
	return append(out, route)
}

func removeRoute(routes []conf.Route, label string) []conf.Route {
	out := make([]conf.Route, 0, len(routes))
	for _, item := range routes {
		if item.Label != label {
			out = append(out, item)
		}
	}
	return out
}

func upsertTriggerRoute(routes []conf.TriggerRoute, route conf.TriggerRoute) []conf.TriggerRoute {
	out := make([]conf.TriggerRoute, 0, len(routes)+1)
	for _, item := range routes {
		if item.Token != route.Token {
			out = append(out, item)
		}
	}
	return append(out, route)
}

func removeTriggerRoute(routes []conf.TriggerRoute, token string) []conf.TriggerRoute {
	out := make([]conf.TriggerRoute, 0, len(routes))
	for _, item := range routes {
		if item.Token != token {
			out = append(out, item)
		}
	}
	return out
}

func formatLeaseRoute(route conf.Route) string {
	return strings.Join([]string{
		route.Label,
		route.IdleTTL,
		fmt.Sprint(routeV4Len(route.IPv4PrefixLen)),
		fmt.Sprint(routeV6Len(route.IPv6PrefixLen)),
		strings.Join(route.IPAllowCIDRs, ","),
	}, " ")
}

func formatTriggerRoute(route conf.TriggerRoute) string {
	return strings.Join([]string{
		route.Token,
		route.Label,
		route.Target,
		route.IdleTTL,
		fmt.Sprint(routeV4Len(route.IPv4PrefixLen)),
		fmt.Sprint(routeV6Len(route.IPv6PrefixLen)),
	}, " ")
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
