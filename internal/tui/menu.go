package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type row struct {
	text   string
	hint   string
	detail string
}

func (m model) updateHome(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if moved, cmd, ok := m.moveCursor(key, 7); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && !m.enterKey(key) {
		return m, nil
	}
	var idx int
	var ok bool
	m, idx, ok = m.handleChoice(key, 7)
	if !ok {
		return m, nil
	}
	m = m.resetNumberBuffer()
	m.cursor = 0
	switch idx {
	case 0:
		m.mode = viewStatus
	case 1:
		m.mode = viewProtect
	case 2:
		m.mode = viewIngress
	case 3:
		m.mode = viewEgress
	case 4:
		m.mode = viewDPI
	case 5:
		m.mode = viewLease
	case 6:
		m.mode = viewDownmask
	}
	m.status = ""
	m.err = ""
	return m, nil
}

func (m model) viewHome() string {
	rows := []row{
		{text: "状态 / 应用", hint: "查看 daemon 状态，应用规则或重载组件", detail: "Enter 进入；用于应用/确认/停用规则和查看 daemon 状态。"},
		{text: "防护", hint: "总开关、公开端口、受保护端口、回滚时间", detail: "Enter 进入；修改配置后仍需在 状态 / 应用 中应用规则。"},
		{text: "入站", hint: "入站白名单、省/市、自定义 CIDR、端口覆盖", detail: "Enter 进入；省市和端口覆盖只写入 DB，应用后才影响规则。"},
		{text: "出站", hint: "出站白名单、省份、自定义 CIDR", detail: "Enter 进入；配置出站允许范围。"},
		{text: "协议封锁", hint: "HTTP/TLS/SOCKS 和跳过端口", detail: "Enter 进入；配置协议封锁开关和跳过端口。"},
		{text: "TCP 租约", hint: "租约服务端、路由、token 触发器", detail: "Enter 进入；配置 TCP 租约服务、路由和公网 token 触发器。"},
		{text: "下行伪装", hint: "服务端、自动拉取、目标和状态", detail: "Enter 进入；配置服务端、自动拉取策略和目标。"},
	}
	return m.renderRows("nwall 配置", rows, "↑/↓/k/j 选择 • Enter/l 进入 • 输入序号后 Enter • q 退出")
}

func (m model) updateStatus(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		return m.goHome(), nil
	}
	if moved, cmd, ok := m.moveCursor(key, 5); ok {
		return moved, cmd
	}
	if !m.isEnterOrNumber(key) && !m.enterKey(key) {
		return m, nil
	}
	var idx int
	m, idx, ok := m.handleChoice(key, 5)
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		return m.confirmAction("确认应用防护规则", fmt.Sprintf("将写入防护规则并启动 %d 秒回滚倒计时。输入 Y 确认执行。", m.cfg.Protect.RollbackTimeoutSec), "Y 确认应用 • 其它键取消 • 0/Esc 返回", viewStatus, func(m *model) error {
			if err := m.actions.Apply(m.cfg, false, 0); err != nil {
				return err
			}
			m.status = fmt.Sprintf("已应用规则；请在 %d 秒内确认，避免自动回滚", m.cfg.Protect.RollbackTimeoutSec)
			m.err = ""
			return nil
		}), nil
	case 1:
		if err := m.actions.Apply(m.cfg, true, 0); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "已应用并确认"
		m.err = ""
	case 2:
		if err := m.actions.Disable(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.cfg.Protect.Enabled = false
		if err := m.saveConfig("已停用防护规则"); err != nil {
			m.setError(err)
			return m, nil
		}
	case 3:
		if err := m.actions.Reload(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "daemon 已重载"
		m.err = ""
	case 4:
		if err := m.refreshStatus(); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = "状态已刷新"
		m.err = ""
	}
	return m, nil
}

func (m *model) refreshStatus() error {
	status, err := m.actions.Status()
	if err != nil {
		return err
	}
	m.daemonStatus = status
	m.hasDaemonStatus = true
	return m.loadPersistent()
}

func (m model) viewStatus() string {
	rows := []row{
		{text: "应用防护规则", hint: "需要输入 Y 确认", detail: "Enter 后进入确认；写入规则并启动回滚倒计时，超时未确认会回滚。"},
		{text: "确认当前规则", hint: "不启动回滚倒计时", detail: "Enter 直接执行 apply --confirm；用于确认当前规则已经可用。"},
		{text: "停用防护规则", hint: "删除规则并关闭 protect.enabled", detail: "Enter 直接删除已应用规则，并把 protect.enabled=false 写入 DB。"},
		{text: "重载 daemon", hint: "重新读取 DB", detail: "Enter 让 daemon 重读 DB 并重启长期组件；不会替代应用防护规则。"},
		{text: "刷新状态", hint: "读取 daemon 状态", detail: "Enter 刷新 daemon 和下行伪装状态快照。"},
	}
	var b strings.Builder
	b.WriteString(m.renderRows("状态 / 应用", rows, "Enter/l 执行当前项 • 输入序号后 Enter • h/0/Esc 返回 • q 退出"))
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("daemon: ") + m.daemonSummary() + "\n")
	b.WriteString(helpStyle.Render("DB: ") + dbPath() + "\n")
	b.WriteString(helpStyle.Render("protect.enabled: ") + fmt.Sprint(m.cfg.Protect.Enabled) + "\n")
	b.WriteString(helpStyle.Render("downmask: ") + m.downmaskStatusSummary() + "\n")
	return b.String()
}

func (m model) daemonSummary() string {
	if !m.hasDaemonStatus {
		return "未刷新"
	}
	parts := []string{fmt.Sprintf("ok=%v", m.daemonStatus.OK)}
	if m.daemonStatus.ReloadedAt != "" {
		parts = append(parts, "reloaded="+m.daemonStatus.ReloadedAt)
	}
	for _, name := range []string{"protect", "dpi", "lease_agent", "lease_trigger", "downmask_server", "downmask_runner"} {
		if c, ok := m.daemonStatus.Components[name]; ok {
			parts = append(parts, name+"="+c.State)
		}
	}
	return strings.Join(parts, " ")
}

func (m model) downmaskStatusSummary() string {
	if !m.hasDownmaskStatus {
		return "无状态快照"
	}
	return fmt.Sprintf("tcp=%v udp=%v active=%d bytes=%d updated=%s",
		m.downmaskStatus.TCPListening, m.downmaskStatus.UDPListening,
		m.downmaskStatus.ActiveSessions, m.downmaskStatus.TotalBytesSent,
		m.downmaskStatus.UpdatedAt)
}

func (m model) goHome() model {
	m.mode = viewHome
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m.resetNumberBuffer()
}

func (m model) renderRows(title string, rows []row, help string) string {
	return m.renderRowsWithIntro(title, rows, "", help)
}

func (m model) renderRowsWithIntro(title string, rows []row, intro, help string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(title) + "\n\n")
	if intro != "" {
		b.WriteString(intro + "\n")
	}
	start, end := visibleRange(m.cursor, len(rows))
	if start > 0 {
		b.WriteString(helpStyle.Render(fmt.Sprintf("... 上方 %d 项", start)) + "\n")
	}
	for i := start; i < end; i++ {
		line := fmt.Sprintf("%d. %s", i+1, rows[i].text)
		if rows[i].hint != "" {
			line += helpStyle.Render("  # " + rows[i].hint)
		}
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	if end < len(rows) {
		b.WriteString(helpStyle.Render(fmt.Sprintf("... 下方 %d 项", len(rows)-end)) + "\n")
	}
	if len(rows) > 0 && m.cursor >= 0 && m.cursor < len(rows) {
		detail := rows[m.cursor].detail
		if detail == "" {
			detail = rows[m.cursor].hint
		}
		if detail != "" {
			b.WriteString("\n" + helpStyle.Render("当前: "+detail) + "\n")
		}
	}
	if m.numBuf != "" {
		b.WriteString(helpStyle.Render("序号: "+m.numBuf+"  Enter 确认") + "\n")
	}
	b.WriteString(m.footer(help))
	return b.String()
}

func visibleRange(cursor, total int) (int, int) {
	if total <= visibleRows {
		return 0, total
	}
	start := cursor - visibleRows/2
	if start < 0 {
		start = 0
	}
	if start+visibleRows > total {
		start = total - visibleRows
	}
	return start, start + visibleRows
}

func (m model) moveCursor(key tea.KeyMsg, total int) (model, tea.Cmd, bool) {
	if total <= 0 {
		m.cursor = 0
		return m.stopRepeat(), nil, false
	}
	switch normalizeMoveKey(key.String()) {
	case "up":
		m = m.resetNumberBuffer()
		if m.cursor > 0 {
			m.cursor--
			m, cmd := m.startRepeat("up", repeatInitialDelay)
			return m, cmd, true
		}
		return m.stopRepeat(), nil, true
	case "down":
		m = m.resetNumberBuffer()
		if m.cursor < total-1 {
			m.cursor++
			m, cmd := m.startRepeat("down", repeatInitialDelay)
			return m, cmd, true
		}
		return m.stopRepeat(), nil, true
	default:
		return m, nil, false
	}
}

func shouldQuit(key tea.KeyMsg) (bool, tea.Cmd) {
	switch key.String() {
	case "q", "ctrl+c":
		return true, tea.Quit
	default:
		return false, nil
	}
}

func (m model) backKey(key tea.KeyMsg) bool {
	switch key.String() {
	case "0", "esc", "backspace", "h":
		if key.String() == "0" && m.currentNumberBuffer() != "" {
			return false
		}
		return true
	default:
		return false
	}
}

func (m model) isEnterOrNumber(key tea.KeyMsg) bool {
	if m.enterKey(key) {
		return true
	}
	_, ok := numericChoice(key.String())
	return ok
}

func (m model) enterKey(key tea.KeyMsg) bool {
	return key.String() == "enter" || key.String() == "l"
}

func (m model) handleChoice(key tea.KeyMsg, total int) (model, int, bool) {
	if m.enterKey(key) {
		if m.numBuf != "" {
			n, ok := numericChoice(m.numBuf)
			if ok && n >= 1 && n <= total {
				return m.resetNumberBuffer(), n - 1, true
			}
			return m.resetNumberBuffer(), 0, false
		}
		if m.cursor >= 0 && m.cursor < total {
			return m, m.cursor, true
		}
		return m, 0, false
	}
	raw := key.String()
	if _, ok := numericChoice(raw); !ok {
		return m, 0, false
	}
	if raw == "0" && m.currentNumberBuffer() == "" {
		return m, 0, false
	}
	candidate := raw
	if len(raw) == 1 {
		candidate = m.currentNumberBuffer() + raw
	}
	n, ok := numericChoice(candidate)
	if !ok || n < 1 || n > total {
		return m.resetNumberBuffer(), 0, false
	}
	if n*10 <= total {
		m.numBuf = candidate
		m.numAt = time.Now()
		return m, 0, false
	}
	return m.resetNumberBuffer(), n - 1, true
}

func numericChoice(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	return n, err == nil
}

func (m model) currentNumberBuffer() string {
	if m.numBuf == "" {
		return ""
	}
	if time.Since(m.numAt) > numberBufferTTL {
		return ""
	}
	return m.numBuf
}

func (m model) resetNumberBuffer() model {
	m.numBuf = ""
	m.numAt = time.Time{}
	return m
}

func isMoveKey(key string) bool {
	return normalizeMoveKey(key) != ""
}

func normalizeMoveKey(key string) string {
	switch key {
	case "up", "k":
		return "up"
	case "down", "j":
		return "down"
	default:
		return ""
	}
}

func (m model) startRepeat(key string, delay time.Duration) (model, tea.Cmd) {
	if m.repeatKey == key {
		m.repeatHits++
	} else {
		m.repeatHits = 1
	}
	m.repeatKey = key
	m.repeatLast = time.Now()
	m.repeatSeq++
	seq := m.repeatSeq
	return m, tea.Tick(delay, func(time.Time) tea.Msg {
		return repeatMsg{key: key, seq: seq}
	})
}

func (m model) stopRepeat() model {
	m.repeatKey = ""
	m.repeatSeq++
	m.repeatHits = 0
	m.repeatLast = time.Time{}
	return m
}
