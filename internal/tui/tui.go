// Package tui implements nwall's interactive configuration UI.
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/daemon"
	"github.com/mora1n/nwall/internal/geo"
	"github.com/mora1n/nwall/internal/store"
)

type storeAPI interface {
	LoadConfig() (conf.Config, error)
	SaveConfig(conf.Config) error
	LoadDownmaskConfig() (store.DownmaskConfig, error)
	SaveDownmaskConfig(store.DownmaskConfig) error
	LoadDownmaskPolicy() (store.DownmaskPolicy, error)
	SaveDownmaskPolicy(store.DownmaskPolicy) error
	LoadDownmaskABPullConfig() (store.DownmaskABPullConfig, error)
	SaveDownmaskABPullConfig(store.DownmaskABPullConfig) error
	LoadDownmaskABTargets() ([]store.DownmaskABTarget, error)
	UpsertDownmaskABTarget(store.DownmaskABTarget) error
	DeleteDownmaskABTarget(string) (bool, error)
	LoadDownmaskStatus() (store.DownmaskStatus, bool, error)
	LoadDownmaskDayState() (store.DownmaskDayState, bool, error)
}

type actionAPI interface {
	Apply(conf.Config, bool, int) error
	Disable() error
	Reload() error
	Status() (daemon.Status, error)
}

type viewMode int

const (
	viewHome viewMode = iota
	viewStatus
	viewProtect
	viewOpenPorts
	viewIngress
	viewIngressPorts
	viewEgress
	viewEgressRegions
	viewDPI
	viewLease
	viewLeaseRoutes
	viewLeaseTrigger
	viewLeaseTriggerRoutes
	viewDownmask
	viewDownmaskServer
	viewDownmaskClient
	viewDownmaskTargets
	viewDownmaskStatus
	viewRegions
	viewProvince
	viewInput
	viewConfirm
	viewPortPolicyMode
	viewPortPolicyRegions
	viewPortPolicyProvince
)

const visibleRows = 18
const numberBufferTTL = 700 * time.Millisecond

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("31"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	errStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	warnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
)

type inputState struct {
	title    string
	help     string
	value    string
	previous viewMode
	submit   func(*model, string) error
}

type confirmState struct {
	title    string
	message  string
	help     string
	previous viewMode
	confirm  func(*model) error
}

type portPolicyDraft struct {
	active bool
	edit   bool
	old    int
	policy conf.PortPolicy
}

type model struct {
	db      storeAPI
	actions actionAPI
	cfg     conf.Config

	downmaskConfig    store.DownmaskConfig
	downmaskPolicy    store.DownmaskPolicy
	downmaskAB        store.DownmaskABPullConfig
	downmaskTargets   []store.DownmaskABTarget
	downmaskStatus    store.DownmaskStatus
	hasDownmaskStatus bool
	downmaskDay       store.DownmaskDayState
	hasDownmaskDay    bool

	daemonStatus    daemon.Status
	hasDaemonStatus bool

	geo        *geo.DB
	mode       viewMode
	cursor     int
	province   string
	regionBack viewMode
	input      inputState
	confirm    confirmState
	portDraft  portPolicyDraft
	numBuf     string
	numAt      time.Time
	status     string
	err        string
}

// Run starts the interactive TUI.
func Run(db *store.DB) error {
	gdb, err := geo.Default()
	if err != nil {
		return err
	}
	m := model{db: db, actions: defaultActions{}, geo: gdb}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.updateKey(msg)
	default:
		return m, nil
	}
}

func (m model) updateKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case viewHome:
		return m.updateHome(key)
	case viewStatus:
		return m.updateStatus(key)
	case viewProtect:
		return m.updateProtect(key)
	case viewOpenPorts:
		return m.updateOpenPorts(key)
	case viewIngress:
		return m.updateIngress(key)
	case viewIngressPorts:
		return m.updateIngressPorts(key)
	case viewEgress:
		return m.updateEgress(key)
	case viewEgressRegions:
		return m.updateEgressRegions(key)
	case viewDPI:
		return m.updateDPI(key)
	case viewLease:
		return m.updateLease(key)
	case viewLeaseRoutes:
		return m.updateLeaseRoutes(key)
	case viewLeaseTrigger:
		return m.updateLeaseTrigger(key)
	case viewLeaseTriggerRoutes:
		return m.updateLeaseTriggerRoutes(key)
	case viewDownmask:
		return m.updateDownmask(key)
	case viewDownmaskServer:
		return m.updateDownmaskServer(key)
	case viewDownmaskClient:
		return m.updateDownmaskClient(key)
	case viewDownmaskTargets:
		return m.updateDownmaskTargets(key)
	case viewDownmaskStatus:
		return m.updateDownmaskStatus(key)
	case viewRegions:
		return m.updateRegions(key)
	case viewProvince:
		return m.updateProvince(key)
	case viewInput:
		return m.updateInput(key)
	case viewConfirm:
		return m.updateConfirm(key)
	case viewPortPolicyMode:
		return m.updatePortPolicyMode(key)
	case viewPortPolicyRegions:
		return m.updatePortPolicyRegions(key)
	case viewPortPolicyProvince:
		return m.updatePortPolicyProvince(key)
	default:
		return m, nil
	}
}

func (m model) View() string {
	switch m.mode {
	case viewStatus:
		return frame(m.viewStatus())
	case viewProtect:
		return frame(m.viewProtect())
	case viewOpenPorts:
		return frame(m.viewOpenPorts())
	case viewIngress:
		return frame(m.viewIngress())
	case viewIngressPorts:
		return frame(m.viewIngressPorts())
	case viewEgress:
		return frame(m.viewEgress())
	case viewEgressRegions:
		return frame(m.viewEgressRegions())
	case viewDPI:
		return frame(m.viewDPI())
	case viewLease:
		return frame(m.viewLease())
	case viewLeaseRoutes:
		return frame(m.viewLeaseRoutes())
	case viewLeaseTrigger:
		return frame(m.viewLeaseTrigger())
	case viewLeaseTriggerRoutes:
		return frame(m.viewLeaseTriggerRoutes())
	case viewDownmask:
		return frame(m.viewDownmask())
	case viewDownmaskServer:
		return frame(m.viewDownmaskServer())
	case viewDownmaskClient:
		return frame(m.viewDownmaskClient())
	case viewDownmaskTargets:
		return frame(m.viewDownmaskTargets())
	case viewDownmaskStatus:
		return frame(m.viewDownmaskStatus())
	case viewRegions:
		return frame(m.viewRegions())
	case viewProvince:
		return frame(m.viewProvince())
	case viewInput:
		return frame(m.viewInput())
	case viewConfirm:
		return frame(m.viewConfirm())
	case viewPortPolicyMode:
		return frame(m.viewPortPolicyMode())
	case viewPortPolicyRegions:
		return frame(m.viewPortPolicyRegions())
	case viewPortPolicyProvince:
		return frame(m.viewPortPolicyProvince())
	default:
		return frame(m.viewHome())
	}
}

func (m *model) loadPersistent() error {
	cfg, err := m.db.LoadConfig()
	if err != nil {
		return err
	}
	dmCfg, err := m.db.LoadDownmaskConfig()
	if err != nil {
		return err
	}
	policy, err := m.db.LoadDownmaskPolicy()
	if err != nil {
		return err
	}
	abCfg, err := m.db.LoadDownmaskABPullConfig()
	if err != nil {
		return err
	}
	targets, err := m.db.LoadDownmaskABTargets()
	if err != nil {
		return err
	}
	dmStatus, hasDMStatus, err := m.db.LoadDownmaskStatus()
	if err != nil {
		return err
	}
	dmDay, hasDMDay, err := m.db.LoadDownmaskDayState()
	if err != nil {
		return err
	}
	m.cfg = cfg
	m.downmaskConfig = dmCfg
	m.downmaskPolicy = policy
	m.downmaskAB = abCfg
	m.downmaskTargets = targets
	m.downmaskStatus = dmStatus
	m.hasDownmaskStatus = hasDMStatus
	m.downmaskDay = dmDay
	m.hasDownmaskDay = hasDMDay
	return nil
}

func (m *model) saveConfig(msg string) error {
	if err := m.db.SaveConfig(m.cfg); err != nil {
		return err
	}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	m.status = msg + "（需要应用或重载后生效）"
	m.err = ""
	return nil
}

func (m *model) saveDownmaskConfig(msg string) error {
	if err := m.db.SaveDownmaskConfig(m.downmaskConfig); err != nil {
		return err
	}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	m.status = msg + "（需要重载 daemon 后生效）"
	m.err = ""
	return nil
}

func (m *model) saveDownmaskPolicy(msg string) error {
	if err := validateDownmaskPolicy(m.downmaskPolicy); err != nil {
		return err
	}
	if err := m.db.SaveDownmaskPolicy(m.downmaskPolicy); err != nil {
		return err
	}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	m.status = msg + "（需要重载 daemon 后生效）"
	m.err = ""
	return nil
}

func (m *model) saveDownmaskAB(msg string) error {
	if err := validateDownmaskAB(m.downmaskAB); err != nil {
		return err
	}
	if err := m.db.SaveDownmaskABPullConfig(m.downmaskAB); err != nil {
		return err
	}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	m.status = msg + "（需要重载 daemon 后生效）"
	m.err = ""
	return nil
}

func (m *model) saveDownmaskTarget(target store.DownmaskABTarget) error {
	if err := validateDownmaskTarget(target); err != nil {
		return err
	}
	if err := m.db.UpsertDownmaskABTarget(target); err != nil {
		return err
	}
	if err := m.loadPersistent(); err != nil {
		return err
	}
	m.status = "已更新下行伪装目标（需要重载 daemon 后生效）"
	m.err = ""
	return nil
}

func (m *model) setError(err error) {
	if err == nil {
		return
	}
	m.err = err.Error()
	m.status = ""
}

func (m model) prompt(title, value, help string, submit func(*model, string) error) model {
	m.input = inputState{
		title:    title,
		value:    value,
		help:     help,
		previous: m.mode,
		submit:   submit,
	}
	m.mode = viewInput
	m.err = ""
	m.status = ""
	return m.resetNumberBuffer()
}

func (m model) updateInput(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.mode = m.input.previous
		m.input = inputState{}
	case "enter":
		submit := m.input.submit
		previous := m.input.previous
		raw := strings.TrimSpace(m.input.value)
		if submit != nil {
			if err := submit(&m, raw); err != nil {
				m.setError(err)
				return m, nil
			}
		}
		if m.mode == viewInput {
			m.mode = previous
		}
	case "backspace", "ctrl+h":
		m.input.value = trimLastRune(m.input.value)
	default:
		if key.Type == tea.KeyRunes {
			m.input.value += string(key.Runes)
		}
	}
	return m, nil
}

func (m model) viewInput() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.input.title) + "\n\n")
	b.WriteString("> " + m.input.value + "\n")
	if m.input.help != "" {
		b.WriteString("\n" + helpStyle.Render(m.input.help) + "\n")
	}
	b.WriteString(m.footer("Enter 保存 • Esc 取消 • Backspace 删除"))
	return b.String()
}

func (m model) footer(help string) string {
	var b strings.Builder
	if m.err != "" {
		b.WriteString("\n" + errStyle.Render("错误: "+m.err) + "\n")
	} else if m.status != "" {
		b.WriteString("\n" + okStyle.Render(m.status) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render(help))
	return b.String()
}

func frame(s string) string {
	return lipgloss.NewStyle().PaddingLeft(2).PaddingRight(2).Render(s)
}

func onOff(v bool) string {
	if v {
		return labelStyle.Render("开启")
	}
	return helpStyle.Render("关闭")
}

func mark(v bool) string {
	if v {
		return "✓"
	}
	return " "
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func joinNonEmpty(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, "，")
}

func routeV4Len(value int) int {
	if value == 0 {
		return 24
	}
	return value
}

func routeV6Len(value int) int {
	if value == 0 {
		return 128
	}
	return value
}

func formatListen(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func dbPath() string {
	if p := os.Getenv("NWALL_DB"); p != "" {
		return p
	}
	return store.DefaultPath
}
