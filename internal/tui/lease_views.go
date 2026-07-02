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
		return m.prompt("TCP 租约共享 key", m.cfg.Lease.LeaseKey, "输入新 key；清空后回车会自动生成；也可用 nwall lease keygen", func(m *model, raw string) error {
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
		m.mode = viewLeaseRoutes
		m.cursor = 0
	case 5:
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
		{text: "临时放行路由: " + countSummary(len(m.cfg.Lease.Routes)), hint: "配置收到租约后临时放行的来源范围"},
		{text: "公网 token 触发器 / 连接来源", hint: fmt.Sprintf("%s routes=%d sources=%d proxies=%d", formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), len(m.cfg.LeaseTrigger.Routes), len(m.cfg.Lease.TrustedRelayCIDRs), len(m.cfg.LeaseTrigger.TrustedProxyCIDRs)), detail: "配置公网 token 入口，以及谁能发送租约、谁能提供真实客户端 IP。"},
	}
	return m.renderRows("TCP 租约", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseTrustedRelays(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.Lease.TrustedRelayCIDRs,
		parent:      viewLeaseTrigger,
		parentRow:   2,
		addTitle:    "新增允许发送租约的来源",
		editTitle:   "修改允许发送租约的来源",
		delTitle:    "删除允许发送租约的来源",
		addStatus:   "已新增允许发送租约的来源",
		editStatus:  "已修改允许发送租约的来源",
		delStatus:   "已删除允许发送租约的来源",
		clearStatus: "已清空允许发送租约的来源",
		hint:        "允许发送租约到本机",
		detail:      "直接发送填发送端 IP/CIDR；中转触发填中转机连接安装机时的出口 IP/CIDR。签名仍会校验。",
		assign: func(m *model, values []string) {
			m.cfg.Lease.TrustedRelayCIDRs = values
		},
	})
}

func (m model) viewLeaseTrustedRelays() string {
	return m.viewCIDRList("TCP 租约 / 连接来源 / 允许发送租约到本机", m.cfg.Lease.TrustedRelayCIDRs, "暂无允许来源", "允许发送租约到本机", "直接发送填发送端 IP/CIDR；中转触发填中转机连接安装机时的出口 IP/CIDR。签名仍会校验。")
}

func (m model) updateLeaseRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.Lease.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLease
		m.cursor = 4
		return m, nil
	}
	switch key.String() {
	case "a":
		route := conf.Route{IdleTTL: valueOr(m.cfg.Lease.IdleTTL, "3d"), IPv4PrefixLen: 24, IPv6PrefixLen: 128}
		return m.promptLeaseRouteLabel("新增临时放行路由", route, ""), nil
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
		return m.promptLeaseRouteLabel("编辑临时放行路由", route, route.Label), nil
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

func (m model) promptLeaseRouteLabel(title string, route conf.Route, oldLabel string) model {
	return m.prompt(title+" / 1 路由名称", route.Label, "给这条临时放行策略起名；发送端和 token 路由会引用它，例如 default", func(m *model, raw string) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("路由名称不能为空")
		}
		route.Label = raw
		*m = m.promptLeaseRouteTTL(title, route, oldLabel)
		return nil
	})
}

func (m model) promptLeaseRouteTTL(title string, route conf.Route, oldLabel string) model {
	return m.prompt(title+" / 2 租约时长", valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), "临时放行保持多久；例如 3d、1h、10m", func(m *model, raw string) error {
		if err := validateTTL(raw); err != nil {
			return err
		}
		route.IdleTTL = raw
		*m = m.promptLeaseRouteIPv4(title, route, oldLabel)
		return nil
	})
}

func (m model) promptLeaseRouteIPv4(title string, route conf.Route, oldLabel string) model {
	value := fmt.Sprint(routeV4Len(route.IPv4PrefixLen))
	return m.prompt(title+" / 3 IPv4 临时放行范围", value, "输入 24-32；24 放行来源所在 /24，32 只放行单 IP", func(m *model, raw string) error {
		v4, err := parseLeaseV4(raw)
		if err != nil {
			return err
		}
		route.IPv4PrefixLen = v4
		*m = m.promptLeaseRouteIPv6(title, route, oldLabel)
		return nil
	})
}

func (m model) promptLeaseRouteIPv6(title string, route conf.Route, oldLabel string) model {
	value := fmt.Sprint(routeV6Len(route.IPv6PrefixLen))
	return m.prompt(title+" / 4 IPv6 临时放行范围", value, "当前仅支持 128，即只放行单个 IPv6 地址", func(m *model, raw string) error {
		v6, err := parseLeaseV6(raw)
		if err != nil {
			return err
		}
		route.IPv6PrefixLen = v6
		*m = m.promptLeaseRouteAllows(title, route, oldLabel)
		return nil
	})
}

func (m model) promptLeaseRouteAllows(title string, route conf.Route, oldLabel string) model {
	return m.prompt(title+" / 5 可使用该路由的来源", strings.Join(route.IPAllowCIDRs, ","), "可选；留空表示任何签名通过的来源都能使用；支持逗号分隔 IP/CIDR", func(m *model, raw string) error {
		allows := []string{}
		var err error
		if strings.TrimSpace(raw) != "" {
			allows, err = parsePrefixList(raw)
			if err != nil {
				return err
			}
		}
		route.IPAllowCIDRs = allows
		if strings.TrimSpace(oldLabel) != "" {
			m.cfg.Lease.Routes = removeRoute(m.cfg.Lease.Routes, oldLabel)
		}
		m.cfg.Lease.Routes = upsertRoute(m.cfg.Lease.Routes, route)
		return m.saveConfig("已更新临时放行路由")
	})
}

func (m model) updateLeaseTrigger(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLease
		m.cursor = 5
		return m, nil
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
		m.mode = viewLeaseTriggerRoutes
		m.cursor = 0
	case 2:
		m.mode = viewLeaseTrustedRelays
		m.cursor = 0
	case 3:
		m.mode = viewLeaseTrustedProxies
		m.cursor = 0
	}
	return m, nil
}

func (m model) updateLeaseTrustedProxies(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	return m.updateCIDRList(key, cidrListOptions{
		values:      m.cfg.LeaseTrigger.TrustedProxyCIDRs,
		parent:      viewLeaseTrigger,
		parentRow:   3,
		addTitle:    "新增反代真实 IP 来源",
		editTitle:   "修改反代真实 IP 来源",
		delTitle:    "删除反代真实 IP 来源",
		addStatus:   "已新增反代真实 IP 来源",
		editStatus:  "已修改反代真实 IP 来源",
		delStatus:   "已删除反代真实 IP 来源",
		clearStatus: "已清空反代真实 IP 来源",
		hint:        "允许这些反代提供真实客户端 IP",
		detail:      "只填 nginx/Caddy/HAProxy 等反代本身的 IP/CIDR；常见为 127.0.0.1,::1。",
		assign: func(m *model, values []string) {
			m.cfg.LeaseTrigger.TrustedProxyCIDRs = values
		},
	})
}

func (m model) viewLeaseTrustedProxies() string {
	return m.viewCIDRList("TCP 租约 / 连接来源 / 反代真实 IP 来源", m.cfg.LeaseTrigger.TrustedProxyCIDRs, "暂无反代来源", "允许这些反代提供真实客户端 IP", "只填 nginx/Caddy/HAProxy 等反代本身的 IP/CIDR；常见为 127.0.0.1,::1。")
}

func (m model) viewLeaseTrigger() string {
	rows := []row{
		{text: "监听: " + formatListen(m.cfg.LeaseTrigger.ListenHost, m.cfg.LeaseTrigger.ListenPort), hint: "公网 token HTTP 入口监听地址"},
		{text: "token 路由: " + countSummary(len(m.cfg.LeaseTrigger.Routes)), hint: "公网 token 请求转成 TCP 租约"},
		{text: "允许发送租约到本机: " + countSummary(len(m.cfg.Lease.TrustedRelayCIDRs)), hint: "直接发送填发送端；中转触发填中转机出口"},
		{text: "反代真实 IP 来源: " + countSummary(len(m.cfg.LeaseTrigger.TrustedProxyCIDRs)), hint: "允许这些反代提供真实客户端 IP"},
	}
	return m.renderRows("TCP 租约 / token 触发器 / 连接来源", rows, "Enter/e 编辑或进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateLeaseTriggerRoutes(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.cfg.LeaseTrigger.Routes)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewLeaseTrigger
		m.cursor = 1
		return m, nil
	}
	switch key.String() {
	case "a":
		route := conf.TriggerRoute{IdleTTL: valueOr(m.cfg.Lease.IdleTTL, "3d"), IPv4PrefixLen: 24, IPv6PrefixLen: 128}
		return m.promptTriggerRouteToken("新增 token 路由", route, ""), nil
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
		return m.promptTriggerRouteToken("编辑 token 路由", route, route.Token), nil
	default:
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) promptTriggerRouteToken(title string, route conf.TriggerRoute, oldToken string) model {
	return m.prompt(title+" / 1 URL token", route.Token, "访问 /<token> 时触发租约；token 不能为空，且不能包含 /", func(m *model, raw string) error {
		if strings.TrimSpace(raw) == "" || strings.Contains(raw, "/") {
			return fmt.Errorf("token 不能为空且不能包含 /")
		}
		route.Token = raw
		*m = m.promptTriggerRouteLabel(title, route, oldToken)
		return nil
	})
}

func (m model) promptTriggerRouteLabel(title string, route conf.TriggerRoute, oldToken string) model {
	return m.prompt(title+" / 2 临时放行路由", route.Label, "填写已有临时放行路由名称；访问 token 后会临时放行该路由计算出的来源范围", func(m *model, raw string) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("临时放行路由不能为空")
		}
		route.Label = raw
		*m = m.promptTriggerRouteTarget(title, route, oldToken)
		return nil
	})
}

func (m model) promptTriggerRouteTarget(title string, route conf.TriggerRoute, oldToken string) model {
	return m.prompt(title+" / 3 安装机 TCP 租约地址", route.Target, "格式 HOST:PORT；无中转机通常填 127.0.0.1:19082，有中转机填安装机内网/公网地址", func(m *model, raw string) error {
		if _, _, err := splitHostPort(raw); err != nil {
			return err
		}
		route.Target = raw
		*m = m.promptTriggerRouteTTL(title, route, oldToken)
		return nil
	})
}

func (m model) promptTriggerRouteTTL(title string, route conf.TriggerRoute, oldToken string) model {
	return m.prompt(title+" / 4 租约时长", valueOr(route.IdleTTL, m.cfg.Lease.IdleTTL), "访问 token 后临时放行多久；例如 3d、1h、10m", func(m *model, raw string) error {
		if err := validateTTL(raw); err != nil {
			return err
		}
		route.IdleTTL = raw
		*m = m.promptTriggerRouteIPv4(title, route, oldToken)
		return nil
	})
}

func (m model) promptTriggerRouteIPv4(title string, route conf.TriggerRoute, oldToken string) model {
	value := fmt.Sprint(routeV4Len(route.IPv4PrefixLen))
	return m.prompt(title+" / 5 IPv4 临时放行范围", value, "输入 24-32；24 放行来源所在 /24，32 只放行单 IP；URL 可用 ?mask=32 覆盖", func(m *model, raw string) error {
		v4, err := parseLeaseV4(raw)
		if err != nil {
			return err
		}
		route.IPv4PrefixLen = v4
		*m = m.promptTriggerRouteIPv6(title, route, oldToken)
		return nil
	})
}

func (m model) promptTriggerRouteIPv6(title string, route conf.TriggerRoute, oldToken string) model {
	value := fmt.Sprint(routeV6Len(route.IPv6PrefixLen))
	return m.prompt(title+" / 6 IPv6 临时放行范围", value, "当前仅支持 128，即只放行单个 IPv6 地址", func(m *model, raw string) error {
		v6, err := parseLeaseV6(raw)
		if err != nil {
			return err
		}
		route.IPv6PrefixLen = v6
		if strings.TrimSpace(oldToken) != "" {
			m.cfg.LeaseTrigger.Routes = removeTriggerRoute(m.cfg.LeaseTrigger.Routes, oldToken)
		}
		m.cfg.LeaseTrigger.Routes = upsertTriggerRoute(m.cfg.LeaseTrigger.Routes, route)
		return m.saveConfig("已更新 token 路由")
	})
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
