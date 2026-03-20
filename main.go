package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RafaelQSantos-RQS/discover-internal-domain/core"
	"github.com/RafaelQSantos-RQS/discover-internal-domain/state"
	"github.com/RafaelQSantos-RQS/discover-internal-domain/tui"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/pflag"
)

const (
	progressTick = 500 * time.Millisecond
	maxMaxLen    = 63
)

// Lipgloss styles for CLI output
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	sectionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	borderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333"))
)

// Flags
var (
	domain     string
	maxLen     int
	workers    int
	timeout    time.Duration
	wildcard   bool
	outFile    string
	maxCombs   int64
	showHelp   bool
	bufferSize int
	checkpoint string
	cacheTTL   time.Duration
	noTUI      bool
)

func init() {
	pflag.BoolVarP(&showHelp, "help", "h", false, "Show this help message")
	pflag.StringVarP(&domain, "domain", "d", "", "Base domain to enumerate (required)")
	pflag.IntVarP(&maxLen, "maxlen", "m", 5, "Maximum length of subdomain combinations")
	pflag.IntVarP(&workers, "workers", "w", runtime.NumCPU(), "Number of concurrent workers")
	pflag.DurationVarP(&timeout, "timeout", "t", 2*time.Second, "Timeout per DNS query")
	pflag.BoolVarP(&wildcard, "wildcard", "W", true, "Enable wildcard detection")
	pflag.StringVarP(&outFile, "out", "o", "", "Output file (default: stdout)")
	pflag.Int64VarP(&maxCombs, "max-combinations", "c", 0, "Maximum number of combinations to generate (0 = unlimited)")
	pflag.IntVarP(&bufferSize, "buffer", "b", 100, "Channel buffer size for job dispatching")
	pflag.StringVarP(&checkpoint, "checkpoint", "k", "", "Checkpoint file for resumable enumeration")
	pflag.DurationVarP(&cacheTTL, "cache-ttl", "l", 5*time.Minute, "Negative DNS cache TTL (0=disabled)")
	pflag.BoolVarP(&noTUI, "no-tui", "", false, "Disable TUI mode (for CI/scripting)")

	pflag.Parse()

	if showHelp {
		fmt.Println("Usage: dnsbrute [options]")
		fmt.Println("")
		fmt.Println("DNS brute-force enumeration tool for discovering internal domains")
		fmt.Println("")
		fmt.Println("Options:")
		pflag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	// Validate flags
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr, "Use --help for usage information")
		os.Exit(1)
	}

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\nInterrupted, shutting down...")
		cancel()
	}()

	// Detect wildcards
	var wildcardIPs []string
	var wildcardStatus string
	if wildcard {
		wildcardIPs = detectWildcards(ctx)
		if len(wildcardIPs) > 0 {
			wildcardStatus = fmt.Sprintf("⚠ wildcard: %s", strings.Join(wildcardIPs[:min(len(wildcardIPs), 2)], ","))
			if len(wildcardIPs) > 2 {
				wildcardStatus += "..."
			}
		} else {
			wildcardStatus = "✓ no wildcard"
		}
	} else {
		wildcardStatus = "disabled"
	}

	// Log configuration with wildcard status
	logConfig(wildcardStatus)

	// Load checkpoint if exists
	var checkpointData *core.CheckpointData
	if checkpoint != "" {
		var err error
		checkpointData, err = core.LoadCheckpoint(checkpoint, domain, maxLen)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("Warning: failed to load checkpoint: %v", err)
			}
		} else {
			log.Printf("Resuming from checkpoint: %d combinations completed\n", checkpointData.Completed)
			if len(checkpointData.WildcardIPs) > 0 {
				log.Printf("Restored wildcard IPs: %v\n", core.FormatWildcardIPs(checkpointData.WildcardIPs))
				wildcardIPs = append(wildcardIPs, checkpointData.WildcardIPs...)
			}
		}
	}

	// Create shared state store
	store := state.NewStore(maxCombs, 100)
	store.SetRunning(true)
	defer store.SetRunning(false)

	// Start TUI if enabled
	if !noTUI {
		go func() {
			if err := tui.Run(store, domain, workers); err != nil {
				log.Printf("TUI error: %v", err)
			}
		}()
	}

	// Create orchestrator
	orch := core.NewOrchestrator(core.Config{
		Domain:          domain,
		Workers:         workers,
		Timeout:         timeout,
		MaxCombinations: maxCombs,
		MaxLen:          maxLen,
		BufferSize:      bufferSize,
		CacheTTL:        cacheTTL,
		CheckpointPath:  checkpoint,
		CheckpointData:  checkpointData,
		WildcardIPs:     wildcardIPs,
	})

	// Progress tracking for non-TUI mode
	var progressMu sync.Mutex
	var totalFound int

	// Run enumeration
	err := orch.Run(
		ctx,
		// onResult callback
		func(fqdn string, ips []string) {
			store.AddResult(fqdn, ips)
			progressMu.Lock()
			totalFound++
			progressMu.Unlock()

			// Print to stdout if not TUI, with timestamp
			if noTUI {
				ts := time.Now().Format("2006-01-02 15:04:05")
				fmt.Printf("[%s] %s -> %s\n", ts, fqdn, strings.Join(ips, ", "))
			}
		},
		// onProgress callback (not used in non-TUI mode)
		func(completed, active int64, speed float64, total int64) {},
		// onDone callback
		func(completed int64, elapsed time.Duration) {
			progressMu.Lock()
			defer progressMu.Unlock()
			if noTUI {
				fmt.Fprintf(os.Stderr, "\n========================================\n")
				fmt.Fprintf(os.Stderr, "  DNS Enumeration Complete\n")
				fmt.Fprintf(os.Stderr, "========================================\n")
				fmt.Fprintf(os.Stderr, "  Total checked:  %d\n", completed)
				fmt.Fprintf(os.Stderr, "  Found:          %d\n", totalFound)
				fmt.Fprintf(os.Stderr, "  Time:           %s\n", elapsed.Round(time.Second))
				fmt.Fprintf(os.Stderr, "========================================\n")
			}
		},
		progressTick,
	)

	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("Enumeration error: %v", err)
	}
}

// detectWildcards performs wildcard detection using a random subdomain probe.
func detectWildcards(ctx context.Context) []string {
	wd, err := core.NewWildcardDetector(ctx, domain, timeout)
	if err != nil || wd == nil {
		return nil
	}
	return wd.WildcardIPs()
}

// validateFlags validates command-line flags.
func validateFlags() error {
	if domain == "" {
		return errors.New("--domain is required")
	}
	if maxLen < 1 {
		return errors.New("--maxlen must be >= 1")
	}
	if maxLen > maxMaxLen {
		maxLen = maxMaxLen
	}
	if workers < 1 {
		return errors.New("--workers must be >= 1")
	}
	if bufferSize < 1 {
		return errors.New("--buffer must be >= 1")
	}
	if cacheTTL < 0 {
		return errors.New("--cache-ttl must be >= 0")
	}
	return nil
}

// centerText centers a string (with ANSI) within a given width
func centerText(s string, width int) string {
	// Calculate visual width without ANSI codes
	visibleWidth := lipgloss.Width(stripANSI(s))
	padding := (width - visibleWidth) / 2
	if padding < 0 {
		padding = 0
	}
	return strings.Repeat(" ", padding) + s
}

// renderConfigTable creates a proper table with rows, columns, and cells
func renderConfigTable(ts, wildcardStatus string) string {
	maxCombsStr := "∞"
	if maxCombs > 0 {
		maxCombsStr = fmt.Sprintf("%d", maxCombs)
	}

	cacheStr := "OFF"
	if cacheTTL > 0 {
		cacheStr = cacheTTL.String()
	}

	// Format wildcard status with icon
	var wildcardIcon, wildcardText string
	if strings.Contains(wildcardStatus, "⚠") {
		wildcardIcon = "⚠️"
		wildcardText = "DETECTED"
	} else if strings.Contains(wildcardStatus, "disabled") {
		wildcardIcon = "🚫"
		wildcardText = "DISABLED"
	} else {
		wildcardIcon = "✅"
		wildcardText = "NONE"
	}

	rows := [][]string{
		{"TARGET", domain},
		{"WORKERS", fmt.Sprintf("%d workers", workers)},
		{"TIMEOUT", timeout.String()},
		{"LENGTH", fmt.Sprintf("≤ %d chars", maxLen)},
		{"MAX", maxCombsStr},
		{"WILDCARD", fmt.Sprintf("%s %s", wildcardIcon, wildcardText)},
		{"CACHE", cacheStr},
		{"BUFFER", fmt.Sprintf("%d", bufferSize)},
		{"STARTED", ts},
	}

	// Calculate REAL width (without ANSI)
	col1 := 0
	col2 := 0

	for _, r := range rows {
		w1 := lipgloss.Width(stripANSI(r[0]))
		w2 := lipgloss.Width(stripANSI(r[1]))

		if w1 > col1 {
			col1 = w1
		}
		if w2 > col2 {
			col2 = w2
		}
	}

	// Styles with fixed width (ESSENTIAL)
	labelCol := lipgloss.NewStyle().
		Width(col1).
		Align(lipgloss.Left).
		Foreground(lipgloss.Color("#888888"))

	valueCol := lipgloss.NewStyle().
		Width(col2).
		Align(lipgloss.Left).
		Foreground(lipgloss.Color("#FFFFFF"))

	headerCol := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4"))

	// Plain border (no lipgloss - causes visual issues when split)
	borderChar := "─"
	borderLeft := "├"
	borderMid := "┼"
	borderRight := "┤"
	borderTopLeft := "┌"
	borderTopMid := "┬"
	borderTopRight := "┐"
	borderBottomLeft := "└"
	borderBottomMid := "┴"
	borderBottomRight := "┘"

	var lines []string

	// Top
	lines = append(lines,
		borderTopLeft+
			strings.Repeat(borderChar, col1+2)+
			borderTopMid+
			strings.Repeat(borderChar, col2+2)+
			borderTopRight,
	)

	// Header
	lines = append(lines,
		fmt.Sprintf("│ %s │ %s │",
			headerCol.Render(labelCol.Render("OPTION")),
			headerCol.Render(valueCol.Render("VALUE")),
		),
	)

	// Separator
	lines = append(lines,
		borderLeft+
			strings.Repeat(borderChar, col1+2)+
			borderMid+
			strings.Repeat(borderChar, col2+2)+
			borderRight,
	)

	// Rows
	for _, r := range rows {
		lines = append(lines,
			fmt.Sprintf("│ %s │ %s │",
				labelCol.Render(r[0]),
				valueCol.Render(r[1]),
			),
		)
	}

	// Bottom
	lines = append(lines,
		borderBottomLeft+
			strings.Repeat(borderChar, col1+2)+
			borderBottomMid+
			strings.Repeat(borderChar, col2+2)+
			borderBottomRight,
	)

	return strings.Join(lines, "\n")
}

// logConfig logs the current configuration.
func logConfig(wildcardStatus string) {
	ts := time.Now().Format("15:04:05")

	if noTUI {
		// Banner
		banner := `██████╗ ███╗   ██╗███████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗    ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║    ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
`
		// Print banner lines centered
		for _, line := range strings.Split(banner, "\n") {
			if line != "" {
				fmt.Println(centerText(headerStyle.Render(line), 80))
			}
		}

		// Config table
		table := renderConfigTable(ts, wildcardStatus)
		// Manual centering
		lines := strings.Split(table, "\n")
		for _, line := range lines {
			fmt.Println(centerText(line, 80))
		}
		fmt.Println()
	} else {
		// Verbose header for TUI mode
		log.Println("========================================")
		log.Println("  DNS Enumeration Configuration")
		log.Println("========================================")
		log.Printf("  Domain:           %s\n", domain)
		log.Printf("  Max Length:       %d\n", maxLen)
		log.Printf("  Workers:          %d\n", workers)
		log.Printf("  Timeout:          %v\n", timeout)
		log.Printf("  Wildcard Check:   %v\n", wildcard)
		if maxCombs > 0 {
			log.Printf("  Max Combinations: %d\n", maxCombs)
		}
		if checkpoint != "" {
			log.Printf("  Checkpoint:       %s\n", checkpoint)
		}
		log.Println("========================================")
	}
}

func boolToStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// stripANSI removes ANSI escape codes for accurate string length calculation
func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

func outFileOrStdout() string {
	if outFile == "" {
		return "(stdout)"
	}
	return outFile
}
