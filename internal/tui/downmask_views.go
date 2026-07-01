package tui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mora1n/nwall/internal/store"
)

func (m model) updateDownmask(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 4); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 4)
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
		{text: "服务端", hint: joinNonEmpty(m.downmaskConfig.TCPAddr, m.downmaskConfig.UDPAddr, "key="+valueOrDash(m.downmaskConfig.Token))},
		{text: "自动拉取", hint: fmt.Sprintf("mode=%s iface=%s targets=%d", m.downmaskPolicy.PullMode, valueOrDash(m.downmaskPolicy.Iface), len(m.downmaskTargets))},
		{text: "目标", hint: countSummary(len(m.downmaskTargets))},
		{text: "状态", hint: m.downmaskStatusSummary()},
	}
	return m.renderRows("下行伪装", rows, "Enter 进入当前项 • 输入序号后 Enter • 0/Esc 返回 • q 退出")
}

func (m model) updateDownmaskServer(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewDownmask
		m.cursor = 0
		return m, nil
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
		return m.prompt("下行伪装共享 key", "", "输入新 key；留空回车自动生成；也可用 openssl rand -hex 16", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				key, err := generateDownmaskKey()
				if err != nil {
					return err
				}
				m.downmaskConfig.Token = key
				return m.saveDownmaskConfig("已生成并保存下行伪装 key: " + key)
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
		return m.prompt("服务端最大速率", formatByteRate(m.downmaskConfig.MaxRate), "服务端发送限速；0 不限；支持 bytes/s、10MB、1GB", func(m *model, raw string) error {
			value, err := parseByteRate(raw, "max_rate")
			if err != nil {
				return err
			}
			m.downmaskConfig.MaxRate = value
			return m.saveDownmaskConfig("已更新服务端最大速率")
		}), nil
	case 5:
		return m.prompt("UDP payload 字节", fmt.Sprint(m.downmaskConfig.UDPPayloadBytes), "UDP 单包数据载荷字节；常用 1200，过大可能分片；范围 17-65507", func(m *model, raw string) error {
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
		{text: "TCP: " + valueOrDash(m.downmaskConfig.TCPAddr), hint: "TCP 客户端拉取伪装流量的监听地址"},
		{text: "UDP: " + valueOrDash(m.downmaskConfig.UDPAddr), hint: "UDP 客户端租用 payload 拉取伪装流量"},
		{text: "共享 key: " + valueOrDash(m.downmaskConfig.Token), hint: "客户端和服务端鉴权；留空自动生成"},
		{text: "seed 路径: " + m.downmaskConfig.SeedPath, hint: "伪装数据源路径，DB 只保存路径"},
		{text: "最大速率: " + formatByteRate(m.downmaskConfig.MaxRate), hint: "服务端发送限速，0 表示不限"},
		{text: fmt.Sprintf("UDP payload: %d", m.downmaskConfig.UDPPayloadBytes), hint: "UDP 单包数据载荷大小，影响分片和包数"},
	}
	return m.renderRows("下行伪装 / 服务端", rows, "Enter/e 编辑 • 0/Esc 返回 • q 退出")
}

func (m model) updateDownmaskClient(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = viewDownmask
		m.cursor = 1
		return m, nil
	}
	if moved, cmd, ok := m.moveCursor(key, 14); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && key.String() != "e" {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 14)
	if key.String() == "e" {
		m = m.resetNumberBuffer()
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
		return m.prompt("默认下行伪装 key", "", "输入新 key；留空回车自动生成；也可用 openssl rand -hex 16", func(m *model, raw string) error {
			if strings.TrimSpace(raw) == "" {
				key, err := generateDownmaskKey()
				if err != nil {
					return err
				}
				m.downmaskAB.Token = key
				return m.saveDownmaskAB("已生成并保存默认下行伪装 key: " + key)
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
		{text: "自动拉取: " + m.downmaskPolicy.PullMode, hint: "Enter 切换是否按下行缺口自动补流量"},
		{text: "统计网卡: " + valueOrDash(m.downmaskPolicy.Iface), hint: "按该网卡统计真实下行量"},
		{text: fmt.Sprintf("每日比例: %.4f - %.4f", m.downmaskPolicy.MinRatio, m.downmaskPolicy.MaxRatio), hint: "每天按区间生成目标伪装比例"},
		{text: "时间窗口: " + joinNonEmpty(m.downmaskPolicy.TimeWindowStart, m.downmaskPolicy.TimeWindowEnd), hint: "仅在该时间段内拉取，留空全天"},
		{text: fmt.Sprintf("最大随机等待: %d 秒", m.downmaskPolicy.MaxJitterSeconds), hint: "每次执行前随机延迟上限"},
		{text: fmt.Sprintf("最小缺口: %d bytes", m.downmaskPolicy.MinDeficitBytes), hint: "低于该缺口不触发拉取"},
		{text: fmt.Sprintf("单次最大拉取: %d bytes", m.downmaskPolicy.MaxBytesPerRun), hint: "限制一次任务最多补多少流量"},
		{text: "协议: " + m.downmaskAB.Protocol, hint: "Enter 切换 tcp/udp；UDP 使用服务端 payload"},
		{text: "协议模式: " + m.downmaskAB.ProtocolMode, hint: "Enter 切换单连接或并行拉取"},
		{text: fmt.Sprintf("默认远端端口: %d", m.downmaskAB.RemotePort), hint: "目标未填端口时使用，0 表示目标端口"},
		{text: "默认本地源 IP: " + valueOrDash(m.downmaskAB.LocalIP), hint: "指定本机出口源 IP，可留空"},
		{text: "默认 key: " + valueOrDash(m.downmaskAB.Token), hint: "默认鉴权 key；留空自动生成"},
		{text: "限速: " + valueOrDash(m.downmaskAB.SpeedLimit), hint: "客户端拉取限速，例如 4M、32Mbps"},
		{text: fmt.Sprintf("超时/并行/抖动: %ds %d %d%% %d%%", m.downmaskAB.TimeoutSeconds, m.downmaskAB.ParallelLimit, m.downmaskAB.SpeedJitterPercent, m.downmaskAB.BytesJitterPercent), hint: "连接超时、并发数和速率/字节随机抖动"},
	}
	return m.renderRows("下行伪装 / 自动拉取", rows, "Enter 切换/编辑 • e 编辑 • 0/Esc 返回 • q 退出")
}

func generateDownmaskKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (m model) updateDownmaskTargets(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	total := len(m.downmaskTargets)
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
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
	case "e", "enter", "l":
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
		if moved, cmd, ok := m.moveCursor(key, total); ok {
			return moved, cmd
		}
		return m, nil
	}
}

func (m model) viewDownmaskTargets() string {
	rows := make([]row, 0, len(m.downmaskTargets))
	for _, target := range m.downmaskTargets {
		rows = append(rows, row{
			text: fmt.Sprintf("%s  port=%d weight=%d tcp=%v udp=%v", target.Host, target.Port, target.Weight, target.TCPEnabled, target.UDPEnabled),
			hint: joinNonEmpty(target.LocalIP, "key="+valueOrDash(target.Token)),
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
	if m.backKey(key) {
		m.mode = viewDownmask
		m.cursor = 3
		return m, nil
	}
	if key.String() == "r" || m.enterKey(key) {
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
