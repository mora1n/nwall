package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/lease"
)

func (m model) updateLease(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 7); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 7)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
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
		return m.prompt("TCP 租约共享 key", "", "输入新 key；留空回车自动生成；也可用 nwall lease keygen", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				key, err := lease.Keygen()
				if err != nil {
					return err
				}
				m.cfg.Lease.LeaseKey = key
				return m.saveConfig("已生成并保存 TCP 租约 key: " + key)
			}
			m.cfg.Lease.LeaseKey = raw
			return m.saveConfig("已更新 TCP 租约 key")
		}), nil
	case 2:
		return m.prompt("默认租约时长", m.cfg.Lease.IdleTTL, "例如 3d、1h、10m", func(m *model, raw string) error {
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
		m.mode = viewLeaseTrustedRelays
		m.cursor = 0
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
		{text: "监听: " + formatListen(m.cfg.Lease.ListenHost, m.cfg.Lease.ListenPort), hint: "安装机接收 TCP 租约请求的地址"},
		{text: "共享 key: " + valueOrDash(m.cfg.Lease.LeaseKey), hint: "客户端签名用；留空自动生成新 key"},
		{text: "默认租约时长: " + m.cfg.Lease.IdleTTL, hint: "未在路由中指定 ttl 时使用"},
		{text: fmt.Sprintf("签名时间窗: %d 秒", m.cfg.Lease.TSWindowSec), hint: "允许的请求时间偏差，防重放"},
		{text: "可信 relay: " + countSummary(len(m.cfg.Lease.TrustedRelayCIDRs)), hint: "允许这些 relay 连接 TCP 租约服务端"},
		{text: "临时放行路由: " + countSummary(len(m.cfg.Lease.Routes)), hint: "配置收到租约后临时放行的来源范围"},
		{text: "token 触发器", hint: fmt.Sprintf("%s routes=%d", formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), len(m.cfg.LeaseTrigger.Routes)), detail: "公网 HTTP token 请求会转成安装机 TCP 租约。"},
	}
	return m.renderRows("TCP 租约", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseTrustedRelays(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.Lease.TrustedRelayCIDRs,
		parent:      viewLease,
		parentRow:   4,
		addTitle:    "新增可信 relay",
		editTitle:   "修改可信 relay",
		delTitle:    "删除可信 relay",
		addStatus:   "已新增可信 relay",
		editStatus:  "已修改可信 relay",
		delStatus:   "已删除可信 relay",
		clearStatus: "已清空可信 relay",
		hint:        "允许连接租约服务端",
		detail:      "只有这些来源可以连接 TCP 租约服务端；签名仍会继续校验。",
		assign: func(m *model, values []string) {
			m.cfg.Lease.TrustedRelayCIDRs = values
		},
	})
}

func (m model) viewLeaseTrustedRelays() string {
	return m.viewCIDRList("TCP 租约 / 可信 relay", m.cfg.Lease.TrustedRelayCIDRs, "暂无可信 relay", "允许连接租约服务端", "只有这些来源可以连接 TCP 租约服务端；签名仍会继续校验。")
}

func (m model) updateLeaseRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Lease.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLease
		m.cursor = 5
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增临时放行路由", "", "格式: <label> <ttl> <v4:24-32> <v6:128> [allow,allow]；例 office 3d 24 128 203.0.113.0/24", func(m *model, raw string) error {
			route, err := parseLeaseRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.Routes = upsertRoute(m.cfg.Lease.Routes, route)
			return m.saveConfig("已更新临时放行路由")
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
		if err := m.saveConfig("已删除临时放行路由: " + label); err != nil {
			m.setError(err)
		}
		return m, nil
	case "e", "enter", "l":
		if total == 0 {
			return m, nil
		}
		route := m.cfg.Lease.Routes[m.cursor]
		return m.prompt("编辑临时放行路由", formatLeaseRoute(route), "label 供发送端/token 路由引用；allow 是可选来源 IP/CIDR 过滤", func(m *model, raw string) error {
			next, err := parseLeaseRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.Lease.Routes = removeRoute(m.cfg.Lease.Routes, route.Label)
			m.cfg.Lease.Routes = upsertRoute(m.cfg.Lease.Routes, next)
			return m.saveConfig("已更新临时放行路由")
		}), nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewLeaseRoutes() string {
	rows := make([]row, 0, len(m.cfg.Lease.Routes))
	for _, route := range m.cfg.Lease.Routes {
		rows = append(rows, row{
			text:   fmt.Sprintf("%s  ttl=%s  v4/%d v6/%d", route.Label, valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), routeV4Len(route.IPv4PrefixLen), routeV6Len(route.IPv6PrefixLen)),
			hint:   valueOrDash(strings.Join(route.IPAllowCIDRs, ",")),
			detail: "收到租约后按该路由临时放行来源；IPv4 默认 /24，mask=32 可改为单 IP。",
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无临时放行路由", hint: "按 a 新增"}}
	}
	return m.renderRows("TCP 租约 / 临时放行路由", rows, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
}

func (m model) updateLeaseTrigger(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLease
		m.cursor = 0
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, 3); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 3)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
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
		m.mode = viewLeaseTrustedProxies
		m.cursor = 0
	case 2:
		m.mode = viewLeaseTriggerRoutes
		m.cursor = 0
	}
	return m, nil
}

func (m model) updateLeaseTrustedProxies(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.LeaseTrigger.TrustedProxyCIDRs,
		parent:      viewLeaseTrigger,
		parentRow:   1,
		addTitle:    "新增可信反代",
		editTitle:   "修改可信反代",
		delTitle:    "删除可信反代",
		addStatus:   "已新增可信反代",
		editStatus:  "已修改可信反代",
		delStatus:   "已删除可信反代",
		clearStatus: "已清空可信反代",
		hint:        "允许提供真实客户端 IP",
		detail:      "只有这些反代来源的 X-Real-IP / X-Forwarded-For 会被信任。",
		assign: func(m *model, values []string) {
			m.cfg.LeaseTrigger.TrustedProxyCIDRs = values
		},
	})
}

func (m model) viewLeaseTrustedProxies() string {
	return m.viewCIDRList("TCP 租约 / token 触发器 / 可信反代", m.cfg.LeaseTrigger.TrustedProxyCIDRs, "暂无可信反代", "允许提供真实客户端 IP", "只有这些反代来源的 X-Real-IP / X-Forwarded-For 会被信任。")
}

func (m model) viewLeaseTrigger() string {
	rows := []row{
		{text: "监听: " + formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), hint: "公网 token HTTP 入口监听地址"},
		{text: "可信反代: " + countSummary(len(m.cfg.LeaseTrigger.TrustedProxyCIDRs)), hint: "允许这些反代提供真实客户端 IP"},
		{text: "token 路由: " + countSummary(len(m.cfg.LeaseTrigger.Routes)), hint: "公网 token 请求转成 TCP 租约"},
	}
	return m.renderRows("TCP 租约 / token 触发器", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseTriggerRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.LeaseTrigger.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLeaseTrigger
		m.cursor = 2
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增 token 路由", "", "格式: <token> <label> <target-host:port> <ttl> <v4:24-32> <v6:128>；例 webtoken office 127.0.0.1:18080 3d 24 128", func(m *model, raw string) error {
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
	case "e", "enter", "l":
		if total == 0 {
			return m, nil
		}
		route := m.cfg.LeaseTrigger.Routes[m.cursor]
		return m.prompt("编辑 token 路由", formatTriggerRoute(route), "token 是 URL 路径；label 对应临时放行路由；target 是安装机 TCP 租约服务端", func(m *model, raw string) error {
			next, err := parseTriggerRoute(raw)
			if err != nil {
				return err
			}
			m.cfg.LeaseTrigger.Routes = removeTriggerRoute(m.cfg.LeaseTrigger.Routes, route.Token)
			m.cfg.LeaseTrigger.Routes = upsertTriggerRoute(m.cfg.LeaseTrigger.Routes, next)
			return m.saveConfig("已更新 token 路由")
		}), nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewLeaseTriggerRoutes() string {
	rows := make([]row, 0, len(m.cfg.LeaseTrigger.Routes))
	for _, route := range m.cfg.LeaseTrigger.Routes {
		rows = append(rows, row{
			text:   fmt.Sprintf("%s  %s -> %s", valueOrDash(route.Token), route.Label, route.Target),
			hint:   fmt.Sprintf("ttl=%s v4/%d v6/%d", valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), routeV4Len(route.IPv4PrefixLen), routeV6Len(route.IPv6PrefixLen)),
			detail: "访问 /<token> 生成 TCP 租约；?mask=32 可把 IPv4 从默认 /24 改为单 IP。",
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无 token 路由", hint: "按 a 新增"}}
	}
	intro := "token 路由把公网 HTTP token 请求转发到安装机 TCP 租约服务端；默认按来源 IPv4 /24 放行。"
	return m.renderRowsWithIntro("TCP 租约 / token 路由", rows, intro, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
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
