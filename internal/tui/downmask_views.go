package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/store"
)

func (m model) updateDownmask(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 4); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 4)
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		m.mode = viewDownmaskServer
	case 1:
		m.mode = viewDownmaskClient
	case 2:
		m.mode = viewDownmaskTargets
	case 3:
		m.mode = viewDownmaskStatus
	}
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m, nil
}

func (m model) viewDownmask() string {
	rows := []row{
		{text: "服务端", hint: joinNonEmpty(m.downmaskConfig.TCPAddr, m.downmaskConfig.UDPAddr, "key="+secretState(m.downmaskConfig.Token))},
		{text: "自动拉取", hint: fmt.Sprintf("mode=%s iface=%s targets=%d", m.downmaskPolicy.PullMode, valueOrDash(m.downmaskPolicy.Iface), len(m.downmaskTargets))},
		{text: "目标", hint: countSummary(len(m.downmaskTargets))},
		{text: "状态", hint: m.downmaskStatusSummary()},
	}
	return m.renderRows("下行伪装", rows, "Enter/序号 进入 • 0/Esc 返回 • q 退出")
}

func (m model) updateDownmaskServer(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewDownmask
		m.cursor = 0
		return m, nil
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
		return m.prompt("下行伪装 TCP 监听", m.downmaskConfig.TCPAddr, "格式 HOST:PORT；留空关闭 TCP", func(m *model, raw string) error {
			if err := validateOptionalListen(raw, "tcp"); err != nil {
				return err
			}
			m.downmaskConfig.TCPAddr = raw
			return m.saveDownmaskConfig("已更新 TCP 监听")
		}), nil
	case 1:
		return m.prompt("下行伪装 UDP 监听", m.downmaskConfig.UDPAddr, "格式 HOST:PORT；留空关闭 UDP", func(m *model, raw string) error {
			if err := validateOptionalListen(raw, "udp"); err != nil {
				return err
			}
			m.downmaskConfig.UDPAddr = raw
			return m.saveDownmaskConfig("已更新 UDP 监听")
		}), nil
	case 2:
		return m.prompt("下行伪装共享 key", "", "输入新 key；不会回显当前值", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				return fmt.Errorf("downmask key 不能为空")
			}
			m.downmaskConfig.Token = raw
			return m.saveDownmaskConfig("已更新下行伪装 key")
		}), nil
	case 3:
		return m.prompt("seed 文件路径", m.downmaskConfig.SeedPath, "DB 只保存路径，不保存 seed 内容", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				raw = store.DefaultDownmaskSeedPath
			}
			m.downmaskConfig.SeedPath = raw
			return m.saveDownmaskConfig("已更新 seed 路径")
		}), nil
	case 4:
		return m.prompt("服务端最大速率", fmt.Sprint(m.downmaskConfig.MaxRate), "bytes/s；0 表示不限", func(m *model, raw string) error {
			value, err := parseUint64(raw, "max_rate")
			if err != nil {
				return err
			}
			m.downmaskConfig.MaxRate = value
			return m.saveDownmaskConfig("已更新服务端最大速率")
		}), nil
	case 5:
		return m.prompt("UDP payload 字节", fmt.Sprint(m.downmaskConfig.UDPPayloadBytes), "范围 17-65507", func(m *model, raw string) error {
			value, err := parseIntRange(raw, "udp_payload_bytes", 17, 65507)
			if err != nil {
				return err
			}
			m.downmaskConfig.UDPPayloadBytes = value
			return m.saveDownmaskConfig("已更新 UDP payload")
		}), nil
	}
	return m, nil
}

func (m model) viewDownmaskServer() string {
	rows := []row{
		{text: "TCP: " + valueOrDash(m.downmaskConfig.TCPAddr), hint: "e 编辑"},
		{text: "UDP: " + valueOrDash(m.downmaskConfig.UDPAddr), hint: "e 编辑"},
		{text: "共享 key: " + secretState(m.downmaskConfig.Token), hint: "e 设置新 key"},
		{text: "seed 路径: " + m.downmaskConfig.SeedPath, hint: "e 编辑"},
		{text: fmt.Sprintf("最大速率: %d", m.downmaskConfig.MaxRate), hint: "e 编辑"},
		{text: fmt.Sprintf("UDP payload: %d", m.downmaskConfig.UDPPayloadBytes), hint: "e 编辑"},
	}
	return m.renderRows("下行伪装 / 服务端", rows, "Enter/e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateDownmaskClient(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewDownmask
		m.cursor = 1
		return m, nil
	}
	if moved, ok := m.moveCursor(key, 14); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 14)
	if key.String() == "e" {
		idx, ok = m.cursor, true
	}
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		if m.downmaskPolicy.PullMode == "ab" {
			m.downmaskPolicy.PullMode = "off"
		} else {
			m.downmaskPolicy.PullMode = "ab"
		}
		if err := m.saveDownmaskPolicy("已切换自动拉取"); err != nil {
			m.setError(err)
		}
	case 1:
		return m.prompt("统计网卡", m.downmaskPolicy.Iface, "例如 eth0；关闭自动拉取时可留空", func(m *model, raw string) error {
			m.downmaskPolicy.Iface = raw
			return m.saveDownmaskPolicy("已更新统计网卡")
		}), nil
	case 2:
		return m.prompt("每日比例范围", fmt.Sprintf("%.4f %.4f", m.downmaskPolicy.MinRatio, m.downmaskPolicy.MaxRatio), "格式: <min> <max>", func(m *model, raw string) error {
			minRatio, maxRatio, err := parseRatioRange(raw)
			if err != nil {
				return err
			}
			m.downmaskPolicy.MinRatio = minRatio
			m.downmaskPolicy.MaxRatio = maxRatio
			return m.saveDownmaskPolicy("已更新每日比例范围")
		}), nil
	case 3:
		return m.prompt("时间窗口", m.downmaskPolicy.TimeWindowStart+" "+m.downmaskPolicy.TimeWindowEnd, "格式: HH:MM HH:MM；留空表示全天", func(m *model, raw string) error {
			start, end, err := parseTimeWindow(raw)
			if err != nil {
				return err
			}
			m.downmaskPolicy.TimeWindowStart = start
			m.downmaskPolicy.TimeWindowEnd = end
			return m.saveDownmaskPolicy("已更新时间窗口")
		}), nil
	case 4:
		return m.prompt("最大随机等待秒数", fmt.Sprint(m.downmaskPolicy.MaxJitterSeconds), "输入 >=0 整数", func(m *model, raw string) error {
			value, err := parseNonNegativeInt(raw, "max_jitter_seconds")
			if err != nil {
				return err
			}
			m.downmaskPolicy.MaxJitterSeconds = value
			return m.saveDownmaskPolicy("已更新最大随机等待")
		}), nil
	case 5:
		return m.prompt("最小缺口字节", fmt.Sprint(m.downmaskPolicy.MinDeficitBytes), "输入 >=0 整数", func(m *model, raw string) error {
			value, err := parseUint64(raw, "min_deficit_bytes")
			if err != nil {
				return err
			}
			m.downmaskPolicy.MinDeficitBytes = value
			return m.saveDownmaskPolicy("已更新最小缺口")
		}), nil
	case 6:
		return m.prompt("单次最大拉取字节", fmt.Sprint(m.downmaskPolicy.MaxBytesPerRun), "输入 >=0 整数", func(m *model, raw string) error {
			value, err := parseUint64(raw, "max_bytes_per_run")
			if err != nil {
				return err
			}
			m.downmaskPolicy.MaxBytesPerRun = value
			return m.saveDownmaskPolicy("已更新单次最大拉取")
		}), nil
	case 7:
		m.downmaskAB.Protocol = nextProtocol(m.downmaskAB.Protocol)
		if err := m.saveDownmaskAB("已切换拉取协议"); err != nil {
			m.setError(err)
		}
	case 8:
		m.downmaskAB.ProtocolMode = nextProtocolMode(m.downmaskAB.ProtocolMode)
		if err := m.saveDownmaskAB("已切换协议模式"); err != nil {
			m.setError(err)
		}
	case 9:
		return m.prompt("默认远端端口", fmt.Sprint(m.downmaskAB.RemotePort), "0 表示使用目标端口；否则 1-65535", func(m *model, raw string) error {
			value, err := parseIntRange(raw, "remote_port", 0, 65535)
			if err != nil {
				return err
			}
			m.downmaskAB.RemotePort = value
			return m.saveDownmaskAB("已更新默认远端端口")
		}), nil
	case 10:
		return m.prompt("默认本地源 IP", m.downmaskAB.LocalIP, "可留空", func(m *model, raw string) error {
			if err := validateOptionalIP(raw, "local_ip"); err != nil {
				return err
			}
			m.downmaskAB.LocalIP = raw
			return m.saveDownmaskAB("已更新默认本地源 IP")
		}), nil
	case 11:
		return m.prompt("默认下行伪装 key", "", "输入新 key；不会回显当前值", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				return fmt.Errorf("downmask key 不能为空")
			}
			m.downmaskAB.Token = raw
			return m.saveDownmaskAB("已更新默认下行伪装 key")
		}), nil
	case 12:
		return m.prompt("限速", m.downmaskAB.SpeedLimit, "例如 4194304、4M、32Mbps；0 表示不限", func(m *model, raw string) error {
			if err := validateRate(raw); err != nil {
				return err
			}
			m.downmaskAB.SpeedLimit = raw
			return m.saveDownmaskAB("已更新限速")
		}), nil
	case 13:
		return m.prompt("超时 / 并行 / 抖动", fmt.Sprintf("%d %d %d %d", m.downmaskAB.TimeoutSeconds, m.downmaskAB.ParallelLimit, m.downmaskAB.SpeedJitterPercent, m.downmaskAB.BytesJitterPercent), "格式: <timeout> <parallel> <speed-jitter%> <bytes-jitter%>", func(m *model, raw string) error {
			timeout, parallel, speedJitter, bytesJitter, err := parseABTunables(raw)
			if err != nil {
				return err
			}
			m.downmaskAB.TimeoutSeconds = timeout
			m.downmaskAB.ParallelLimit = parallel
			m.downmaskAB.SpeedJitterPercent = speedJitter
			m.downmaskAB.BytesJitterPercent = bytesJitter
			return m.saveDownmaskAB("已更新拉取参数")
		}), nil
	}
	return m, nil
}

func (m model) viewDownmaskClient() string {
	rows := []row{
		{text: "自动拉取: " + m.downmaskPolicy.PullMode, hint: "Enter 切换 off/ab"},
		{text: "统计网卡: " + valueOrDash(m.downmaskPolicy.Iface), hint: "e 编辑"},
		{text: fmt.Sprintf("每日比例: %.4f - %.4f", m.downmaskPolicy.MinRatio, m.downmaskPolicy.MaxRatio), hint: "e 编辑"},
		{text: "时间窗口: " + joinNonEmpty(m.downmaskPolicy.TimeWindowStart, m.downmaskPolicy.TimeWindowEnd), hint: "e 编辑"},
		{text: fmt.Sprintf("最大随机等待: %d 秒", m.downmaskPolicy.MaxJitterSeconds), hint: "e 编辑"},
		{text: fmt.Sprintf("最小缺口: %d bytes", m.downmaskPolicy.MinDeficitBytes), hint: "e 编辑"},
		{text: fmt.Sprintf("单次最大拉取: %d bytes", m.downmaskPolicy.MaxBytesPerRun), hint: "e 编辑"},
		{text: "协议: " + m.downmaskAB.Protocol, hint: "Enter 切换 tcp/udp"},
		{text: "协议模式: " + m.downmaskAB.ProtocolMode, hint: "Enter 切换 single/parallel"},
		{text: fmt.Sprintf("默认远端端口: %d", m.downmaskAB.RemotePort), hint: "e 编辑"},
		{text: "默认本地源 IP: " + valueOrDash(m.downmaskAB.LocalIP), hint: "e 编辑"},
		{text: "默认 key: " + secretState(m.downmaskAB.Token), hint: "e 设置新 key"},
		{text: "限速: " + valueOrDash(m.downmaskAB.SpeedLimit), hint: "e 编辑"},
		{text: fmt.Sprintf("超时/并行/抖动: %ds %d %d%% %d%%", m.downmaskAB.TimeoutSeconds, m.downmaskAB.ParallelLimit, m.downmaskAB.SpeedJitterPercent, m.downmaskAB.BytesJitterPercent), hint: "e 编辑"},
	}
	return m.renderRows("下行伪装 / 自动拉取", rows, "Enter 切换/编辑 • e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateDownmaskTargets(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.downmaskTargets)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewDownmask
		m.cursor = 2
		return m, nil
	}
	switch key.String() {
	case "a":
		return m.prompt("新增下行伪装目标", "", "格式: <host> <port> <weight> <tcp:true|false> <udp:true|false> [local-ip] [key]", func(m *model, raw string) error {
			target, err := parseDownmaskTarget(raw)
			if err != nil {
				return err
			}
			return m.saveDownmaskTarget(target)
		}), nil
	case "d":
		if total == 0 {
			return m, nil
		}
		host := m.downmaskTargets[m.cursor].Host
		ok, err := m.db.DeleteDownmaskABTarget(host)
		if err != nil {
			m.setError(err)
			return m, nil
		}
		if !ok {
			m.setError(fmt.Errorf("未找到下行伪装目标: %s", host))
			return m, nil
		}
		if err := m.loadPersistent(); err != nil {
			m.setError(err)
			return m, nil
		}
		if m.cursor >= len(m.downmaskTargets) && m.cursor > 0 {
			m.cursor--
		}
		m.status = "已删除下行伪装目标（需要重载 daemon 后生效）"
		m.err = ""
		return m, nil
	case "e", "enter":
		if total == 0 {
			return m, nil
		}
		target := m.downmaskTargets[m.cursor]
		return m.prompt("编辑下行伪装目标", formatDownmaskTarget(target), "格式: <host> <port> <weight> <tcp:true|false> <udp:true|false> [local-ip] [key]", func(m *model, raw string) error {
			next, err := parseDownmaskTarget(raw)
			if err != nil {
				return err
			}
			if next.Host != target.Host {
				if _, err := m.db.DeleteDownmaskABTarget(target.Host); err != nil {
					return err
				}
			}
			return m.saveDownmaskTarget(next)
		}), nil
	default:
		if moved, ok := m.moveCursor(key, total); ok {
			return moved, nil
		}
		return m, nil
	}
}

func (m model) viewDownmaskTargets() string {
	rows := make([]row, 0, len(m.downmaskTargets))
	for _, target := range m.downmaskTargets {
		rows = append(rows, row{
			text: fmt.Sprintf("%s  port=%d weight=%d tcp=%v udp=%v", target.Host, target.Port, target.Weight, target.TCPEnabled, target.UDPEnabled),
			hint: joinNonEmpty(target.LocalIP, "key="+secretState(target.Token)),
		})
	}
	if len(rows) == 0 {
		rows = []row{{text: "暂无下行伪装目标", hint: "按 a 新增"}}
	}
	return m.renderRows("下行伪装 / 目标", rows, "a 新增 • e/Enter 编辑 • d 删除 • 0/Esc 返回")
}

func (m model) updateDownmaskStatus(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		m.mode = viewDownmask
		m.cursor = 3
		return m, nil
	}
	if key.String() == "r" || key.String() == "enter" {
		if err := m.loadPersistent(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "下行伪装状态已刷新"
		m.err = ""
	}
	return m, nil
}

func (m model) viewDownmaskStatus() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("下行伪装 / 状态") + "\n\n")
	if m.hasDownmaskStatus {
		b.WriteString(fmt.Sprintf("server_tcp: %v\n", m.downmaskStatus.TCPListening))
		b.WriteString(fmt.Sprintf("server_udp: %v\n", m.downmaskStatus.UDPListening))
		b.WriteString(fmt.Sprintf("active_sessions: %d\n", m.downmaskStatus.ActiveSessions))
		b.WriteString(fmt.Sprintf("total_bytes_sent: %d\n", m.downmaskStatus.TotalBytesSent))
		b.WriteString(fmt.Sprintf("updated_at: %s\n", m.downmaskStatus.UpdatedAt))
	} else {
		b.WriteString("server_status: 无状态快照\n")
	}
	if m.hasDownmaskDay {
		b.WriteString(fmt.Sprintf("date: %s\n", m.downmaskDay.Date))
		b.WriteString(fmt.Sprintf("target_ratio: %.4f\n", m.downmaskDay.TargetRatio))
		b.WriteString(fmt.Sprintf("rx_accum: %d\n", m.downmaskDay.RXAccum))
		b.WriteString(fmt.Sprintf("tx_accum: %d\n", m.downmaskDay.TXAccum))
		b.WriteString(fmt.Sprintf("last_action: %s\n", m.downmaskDay.LastAction))
		b.WriteString(fmt.Sprintf("last_error: %s\n", valueOrDash(m.downmaskDay.LastError)))
	} else {
		b.WriteString("day_state: 无状态快照\n")
	}
	b.WriteString(m.footer("r/Enter 刷新 • 0/Esc 返回 • q 退出"))
	return b.String()
}

func nextProtocol(value string) string {
	if value == "udp" {
		return "tcp"
	}
	return "udp"
}

func nextProtocolMode(value string) string {
	if value == "parallel" {
		return "single"
	}
	return "parallel"
}

func formatDownmaskTarget(target store.DownmaskABTarget) string {
	return strings.Join([]string{
		target.Host,
		fmt.Sprint(target.Port),
		fmt.Sprint(target.Weight),
		fmt.Sprint(target.TCPEnabled),
		fmt.Sprint(target.UDPEnabled),
		target.LocalIP,
		target.Token,
	}, " ")
}
