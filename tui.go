package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TUI Styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	statsStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	progressBarEmpty = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#444444"))

	progressBarFilled = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#7D56F4"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))
)

// DNS Result item for the list
type dnsResult struct {
	fqdn string
	ips  string
}

func (d dnsResult) Title() string       { return d.fqdn }
func (d dnsResult) Description() string { return d.ips }
func (d dnsResult) FilterValue() string { return d.fqdn }

// TUI Messages
type resultMsg struct {
	fqdn string
	ips  []string
}

type progressMsg struct {
	completed  int64
	activeJobs int64
	speed      float64
	total      int64
}

type doneMsg struct {
	totalDiscovered int
	elapsed         time.Duration
}

// TUI Model
type tuiModel struct {
	list       list.Model
	completed  int64
	total      int64
	activeJobs int64
	speed      float64
	elapsed    time.Duration
	startTime  time.Time
	results    []dnsResult
	quitting   bool
	width      int
	height     int
}

// Styles for the list items
func newListModel(height int) list.Model {
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, height)
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetShowStatusBar(false)
	return l
}

func newTUIModel(width, height int) *tuiModel {
	return &tuiModel{
		list:      newListModel(height - 10),
		startTime: time.Now(),
		width:     width,
		height:    height,
		results:   make([]dnsResult, 0, 100),
	}
}

func (m *tuiModel) Init() tea.Cmd {
	return nil
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetHeight(msg.Height - 10)

	case resultMsg:
		item := dnsResult{
			fqdn: msg.fqdn,
			ips:  strings.Join(msg.ips, ", "),
		}
		m.results = append(m.results, item)
		if len(m.results) > 100 {
			m.results = m.results[1:]
		}
		items := make([]list.Item, len(m.results))
		for i, r := range m.results {
			items[i] = r
		}
		m.list.SetItems(items)

	case progressMsg:
		m.completed = msg.completed
		m.activeJobs = msg.activeJobs
		m.speed = msg.speed
		m.total = msg.total
		m.elapsed = time.Since(m.startTime)

	case doneMsg:
		m.quitting = true
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

		// Delegate list updates
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd

	default:
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *tuiModel) View() string {
	// Progress bar
	progressStr := m.renderProgressBar()

	// Stats line
	statsStr := m.renderStats()

	// Results list
	listStr := m.list.View()

	// Footer
	footer := footerStyle.Render("Press Ctrl+C to stop • q to quit")

	// Build full view
	var sb strings.Builder
	sb.WriteString(headerStyle.Render(fmt.Sprintf(" 🔍 dnsbrute - Enumerating %s", domain)))
	sb.WriteString("\n")
	sb.WriteString(progressStr)
	sb.WriteString("\n")
	sb.WriteString(statsStyle.Render(statsStr))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", m.width))
	sb.WriteString("\n")
	sb.WriteString(listStr)
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", m.width))
	sb.WriteString("\n")
	sb.WriteString(footer)

	return sb.String()
}

func (m *tuiModel) renderProgressBar() string {
	var sb strings.Builder
	sb.WriteString(" Progress: ")

	barWidth := m.width - 50
	if barWidth < 10 {
		barWidth = 30
	}

	var percentage float64
	if m.total > 0 {
		percentage = float64(m.completed) / float64(m.total)
	}

	filled := int(percentage * float64(barWidth))
	empty := barWidth - filled

	sb.WriteString(progressBarFilled.Render(strings.Repeat("█", filled)))
	sb.WriteString(progressBarEmpty.Render(strings.Repeat("░", empty)))
	sb.WriteString(" ")

	if m.total > 0 {
		sb.WriteString(fmt.Sprintf("%.1f%% (%d/%d)", percentage*100, m.completed, m.total))
	} else {
		sb.WriteString(fmt.Sprintf("%d completed", m.completed))
	}

	return sb.String()
}

func (m *tuiModel) renderStats() string {
	return fmt.Sprintf(" Speed: %.1f req/s | Active: %d | Workers: %d | Elapsed: %s",
		m.speed, m.activeJobs, workers, m.elapsed.Round(time.Second))
}

// TUI Runner
type TUIRunner struct {
	resultCh   chan resultMsg
	progressCh chan progressMsg
	doneCh     chan struct{}
	program    *tea.Program
	active     bool
}

func newTUIRunner() *TUIRunner {
	return &TUIRunner{
		resultCh:   make(chan resultMsg, 100),
		progressCh: make(chan progressMsg, 10),
		doneCh:     make(chan struct{}),
		active:     false,
	}
}

func (t *TUIRunner) Start() bool {
	go func() {
		initialModel := newTUIModel(100, 30)
		p := tea.NewProgram(initialModel, tea.WithAltScreen())
		t.program = p
		t.active = true
		go t.messageLoop()
		if _, err := p.Run(); err != nil {
			// TUI closed
			t.active = false
		}
	}()

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)
	return t.active
}

func (t *TUIRunner) messageLoop() {
	for {
		select {
		case r := <-t.resultCh:
			if t.program != nil && t.active {
				t.program.Send(r)
			}
		case p := <-t.progressCh:
			if t.program != nil && t.active {
				t.program.Send(p)
			}
		case <-t.doneCh:
			if t.program != nil && t.active {
				t.program.Send(doneMsg{
					totalDiscovered: 0,
					elapsed:         time.Since(time.Now()),
				})
				t.program.Quit()
			}
			return
		}
	}
}

func (t *TUIRunner) Stop() {
	if t.active {
		t.doneCh <- struct{}{}
	}
}

func (t *TUIRunner) IsActive() bool {
	return t.active
}

func (t *TUIRunner) SendResult(fqdn string, ips []string) {
	if !t.active {
		return
	}
	select {
	case t.resultCh <- resultMsg{fqdn: fqdn, ips: ips}:
	default:
		// Channel full, skip
	}
}

func (t *TUIRunner) SendProgress(completed, activeJobs int64, speed float64) {
	if !t.active {
		return
	}
	select {
	case t.progressCh <- progressMsg{completed: completed, activeJobs: activeJobs, speed: speed, total: maxCombs}:
	default:
		// Channel full, skip
	}
}
