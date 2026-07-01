package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type row struct {
	text string
	hint string
}

func (m model) updateHome(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if moved, ok := m.moveCursor(key, 7); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 7)
	if !ok {
		return m, nil
	}
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
		{text: "状态 / 应用", hint: "查看 daemon 状态，应用规则或重载组件"},
		{text: "防护", hint: "总开关、公开端口、受保护端口、回滚时间"},
		{text: "入站", hint: "入站白名单、省/市、自定义 CIDR、端口覆盖"},
		{text: "出站", hint: "出站白名单、省份、自定义 CIDR"},
		{text: "协议封锁", hint: "HTTP/TLS/SOCKS 和跳过端口"},
		{text: "TCP 租约", hint: "租约服务端、路由、token 触发器"},
		{text: "下行伪装", hint: "服务端、自动拉取、目标和状态"},
	}
	return m.renderRows("nwall 配置", rows, "↑/↓ 选择 • Enter/序号 进入 • q 退出")
}

func (m model) updateStatus(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if backKey(key) {
		return m.goHome(), nil
	}
	if moved, ok := m.moveCursor(key, 5); ok {
		return moved, nil
	}
	if !isEnterOrNumber(key) {
		return m, nil
	}
	idx, ok := chosenIndex(key, m.cursor, 5)
	if !ok {
		return m, nil
	}
	switch idx {
	case 0:
		if err := m.actions.Apply(m.cfg, false, 0); err != nil {
			m.setError(err)
			return m, nil
		}
		m.status = fmt.Sprintf("已应用规则；请在 %d 秒内确认，避免自动回滚", m.cfg.Protect.RollbackTimeoutSec)
		m.err = ""
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
		{text: "应用防护规则", hint: "写入 nft 规则并启动回滚倒计时"},
		{text: "确认当前规则", hint: "应用并确认，不启动回滚倒计时"},
		{text: "停用防护规则", hint: "删除已应用的 nft 表，并写入 protect.enabled=false"},
		{text: "重载 daemon", hint: "重新读取 DB 并重启长期组件"},
		{text: "刷新状态", hint: "读取 daemon 和下行伪装状态"},
	}
	var b strings.Builder
	b.WriteString(m.renderRows("状态 / 应用", rows, "Enter/序号 执行 • 0/Esc 返回 • q 退出"))
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
	return m
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

func (m model) moveCursor(key tea.KeyMsg, total int) (model, bool) {
	if total <= 0 {
		m.cursor = 0
		return m, false
	}
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, true
	case "down", "j":
		if m.cursor < total-1 {
			m.cursor++
		}
		return m, true
	default:
		return m, false
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

func backKey(key tea.KeyMsg) bool {
	switch key.String() {
	case "0", "esc", "backspace":
		return true
	default:
		return false
	}
}

func isEnterOrNumber(key tea.KeyMsg) bool {
	if key.String() == "enter" {
		return true
	}
	_, ok := numericChoice(key.String())
	return ok
}

func chosenIndex(key tea.KeyMsg, cursor, total int) (int, bool) {
	if key.String() == "enter" {
		if cursor >= 0 && cursor < total {
			return cursor, true
		}
		return 0, false
	}
	n, ok := numericChoice(key.String())
	if !ok || n < 1 || n > total {
		return 0, false
	}
	return n - 1, true
}

func numericChoice(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	return n, err == nil
}
