// Package tui provides the BubbleTea-based terminal UI for DNS enumeration.
// It uses a pull model where the UI reads from the shared state store on tick intervals,
// eliminating the need for workers to send events directly to the TUI.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RafaelQSantos-RQS/discover-internal-domain/state"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Ticker interval for UI updates
const tickInterval = 250 * time.Millisecond

// Styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	statsStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))
)

// DNSResultItem represents a result in the list.
type DNSResultItem struct {
	fqdn string
	ips  string
}

func (d DNSResultItem) Title() string       { return d.fqdn }
func (d DNSResultItem) Description() string { return d.ips }
func (d DNSResultItem) FilterValue() string { return d.fqdn }

// Model is the BubbleTea model for the DNS enumeration TUI.
type Model struct {
	list     list.Model
	progress progress.Model

	// Shared state (read on each tick)
	store *state.Store

	// Local UI state
	width    int
	height   int
	workers  int
	quitting bool
	domain   string
}

// NewModel creates a new TUI model.
func NewModel(store *state.Store, domain string, workers int, width, height int) *Model {
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, height-12)
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetShowStatusBar(false)

	return &Model{
		list:     l,
		progress: progress.New(progress.WithDefaultGradient()),
		store:    store,
		width:    width,
		height:   height,
		workers:  workers,
		domain:   domain,
	}
}

// Init implements tea.Model.Init.
// Returns a tick command to trigger periodic state reads.
func (m *Model) Init() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg {
		return tickMsg{t}
	})
}

// tickMsg is sent on each tick interval.
type tickMsg struct {
	time time.Time
}

// Update implements tea.Model.Update.
// This is where the pull model is implemented - we read from state on each tick.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetHeight(msg.Height - 12)
		return m, nil

	case tickMsg:
		// PULL MODEL: Read current state from the store
		if m.store.IsRunning() {
			// Update list with current results (safe copy)
			results := m.store.Results()
			items := make([]list.Item, len(results))
			for i, r := range results {
				items[i] = DNSResultItem{
					fqdn: r.FQDN,
					ips:  strings.Join(r.IPs, ", "),
				}
			}
			m.list.SetItems(items)
		}

		// Re-schedule the next tick
		return m, tea.Tick(tickInterval, func(t time.Time) tea.Msg {
			return tickMsg{t}
		})

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

		// Delegate to list
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd

	default:
		// Delegate to list for other messages
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
}

// View implements tea.Model.View.
func (m *Model) View() string {
	// Get current state snapshot
	completed, active, speed, total, elapsed := m.store.Snapshot()

	// Calculate progress
	var percent float64
	if total > 0 {
		percent = float64(completed) / float64(total)
		m.progress.SetPercent(percent)
	} else {
		// Indeterminate mode for unknown total
		m.progress.SetPercent(0)
	}

	// Build view
	var sb strings.Builder

	// Header
	sb.WriteString(headerStyle.Render(fmt.Sprintf(" 🔍 dnsbrute - Enumerating %s", m.domain)))
	sb.WriteString("\n\n")

	// Stats
	sb.WriteString(m.renderStats(completed, active, speed, total, elapsed))
	sb.WriteString("\n\n")

	// Progress bar
	sb.WriteString(m.progress.View())
	sb.WriteString("\n\n")

	// Separator
	sb.WriteString(strings.Repeat("─", min(m.width, 80)))
	sb.WriteString("\n")

	// Results list
	sb.WriteString(m.list.View())
	sb.WriteString("\n")

	// Footer
	sb.WriteString(strings.Repeat("─", min(m.width, 80)))
	sb.WriteString("\n")
	sb.WriteString(footerStyle.Render("Press Ctrl+C to stop • q to quit"))

	return sb.String()
}

// renderStats formats the statistics line.
func (m *Model) renderStats(completed, active int64, speed float64, total int64, elapsed time.Duration) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(" %d/%d completed", completed, total))
	sb.WriteString(fmt.Sprintf(" | Speed: %.1f req/s", speed))
	sb.WriteString(fmt.Sprintf(" | Active: %d", active))
	sb.WriteString(fmt.Sprintf(" | Workers: %d", m.workers))
	sb.WriteString(fmt.Sprintf(" | Elapsed: %s", elapsed.Round(time.Second)))
	return statsStyle.Render(sb.String())
}

// Run starts the TUI and returns when the user quits.
func Run(store *state.Store, domain string, workers int) error {
	p := tea.NewProgram(
		NewModel(store, domain, workers, 100, 30),
		tea.WithAltScreen(),
	)
	_, err := p.Run()
	return err
}
