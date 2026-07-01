package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) confirmAction(title, message, help string, previous viewMode, submit func(*model) error) model {
	m.mode = viewConfirm
	m.confirm = confirmState{
		title:    title,
		message:  message,
		help:     help,
		previous: previous,
		confirm:  submit,
	}
	m.cursor = 0
	m.status = ""
	m.err = ""
	return m.resetNumberBuffer()
}

func (m model) updateConfirm(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if quit, cmd := shouldQuit(key); quit {
		return m, cmd
	}
	if m.backKey(key) {
		m.mode = m.confirm.previous
		m.status = "已取消"
		m.err = ""
		return m.resetNumberBuffer(), nil
	}
	if key.Type == tea.KeyRunes && strings.EqualFold(string(key.Runes), "y") {
		submit := m.confirm.confirm
		m.mode = m.confirm.previous
		m.confirm = confirmState{}
		if submit != nil {
			if err := submit(&m); err != nil {
				m.setError(err)
			}
		}
		return m.resetNumberBuffer(), nil
	}
	if m.enterKey(key) {
		return m, nil
	}
	m.mode = m.confirm.previous
	m.status = "已取消"
	m.err = ""
	return m.resetNumberBuffer(), nil
}

func (m model) viewConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.confirm.title) + "\n\n")
	b.WriteString(m.confirm.message + "\n\n")
	b.WriteString(m.footer(m.confirm.help))
	return b.String()
}
