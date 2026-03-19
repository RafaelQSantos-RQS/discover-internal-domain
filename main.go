package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

const (
	maxMaxLen    = 63                     // DNS label max length
	maxNegCache  = 100_000                // Max entries in negative cache
	maxGrowSize  = maxMaxLen + 10         // Max size for strings.Builder.Grow()
	progressTick = 500 * time.Millisecond // Progress bar update interval
)

// Existing flags
var (
	domain   string
	maxLen   int
	workers  int
	timeout  time.Duration
	wildcard bool
	outFile  string
	maxCombs int64
	showHelp bool
)

// New flags for performance optimization
var (
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

	// New performance flags
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

	// Validation
	if domain == "" {
		fmt.Fprintln(os.Stderr, "Error: --domain is required")
		fmt.Fprintln(os.Stderr, "Use --help for usage information")
		os.Exit(1)
	}
	if maxLen < 1 {
		fmt.Fprintln(os.Stderr, "Error: --maxlen must be >= 1")
		os.Exit(1)
	}
	if maxLen > maxMaxLen {
		fmt.Fprintf(os.Stderr, "Error: --maxlen capped at %d (DNS label limit)\n", maxMaxLen)
		maxLen = maxMaxLen
	}
	if workers < 1 {
		fmt.Fprintln(os.Stderr, "Error: --workers must be >= 1")
		os.Exit(1)
	}
	if bufferSize < 1 {
		fmt.Fprintln(os.Stderr, "Error: --buffer must be >= 1")
		os.Exit(1)
	}
	if cacheTTL < 0 {
		fmt.Fprintln(os.Stderr, "Error: --cache-ttl must be >= 0")
		os.Exit(1)
	}
}

// negCache with hard limit for memory safety
type negCache struct {
	mu         sync.RWMutex
	cache      map[string]time.Time
	access     []string // LRU tracking (oldest first)
	maxEntries int
	ttl        time.Duration
}

func newNegCache(ttl time.Duration) *negCache {
	return &negCache{
		cache:      make(map[string]time.Time),
		access:     make([]string, 0, maxNegCache),
		maxEntries: maxNegCache,
		ttl:        ttl,
	}
}

func (nc *negCache) isCached(fqdn string) bool {
	if nc.ttl == 0 {
		return false
	}
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	if expire, ok := nc.cache[fqdn]; ok {
		return time.Now().Before(expire)
	}
	return false
}

func (nc *negCache) add(fqdn string) {
	if nc.ttl == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Evict oldest entries if at capacity
	for len(nc.cache) >= nc.maxEntries && len(nc.access) > 0 {
		oldest := nc.access[0]
		nc.access = nc.access[1:]
		delete(nc.cache, oldest)
	}

	nc.cache[fqdn] = time.Now().Add(nc.ttl)
	nc.access = append(nc.access, fqdn)
}

func (nc *negCache) cleanup() {
	if nc.ttl == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()
	now := time.Now()

	newAccess := make([]string, 0, len(nc.access))
	for _, fqdn := range nc.access {
		if expire, ok := nc.cache[fqdn]; ok && now.After(expire) {
			delete(nc.cache, fqdn)
		} else {
			newAccess = append(newAccess, fqdn)
		}
	}
	nc.access = newAccess
}

// Checkpoint data structure
type checkpointData struct {
	Completed   int64     `json:"completed"`
	LastIndex   []int     `json:"last_index"`
	Length      int       `json:"length"`
	Timestamp   time.Time `json:"timestamp"`
	MaxLen      int       `json:"max_len"`
	Domain      string    `json:"domain"`
	WildcardIPs []string  `json:"wildcard_ips,omitempty"`
}

// Progress tracking
type progress struct {
	completed  atomic.Int64
	activeJobs atomic.Int64
	mu         sync.RWMutex
	lastCount  int64
	lastTime   time.Time
	startTime  time.Time
	muPrint    sync.Mutex
}

func newProgress() *progress {
	return &progress{
		lastTime:  time.Now(),
		startTime: time.Now(),
	}
}

func (p *progress) increment() {
	p.completed.Add(1)
}

func (p *progress) jobStarted() {
	p.activeJobs.Add(1)
}

func (p *progress) jobFinished() {
	p.activeJobs.Add(-1)
}

func (p *progress) speed() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	elapsed := now.Sub(p.lastTime).Seconds()
	if elapsed < 0.1 {
		return 0
	}

	count := p.completed.Load()
	speed := float64(count-p.lastCount) / elapsed
	return speed
}

func (p *progress) snapshot() (completed int64, speed float64, active int64) {
	p.mu.Lock()
	p.lastCount = p.completed.Load()
	p.lastTime = time.Now()
	p.mu.Unlock()

	return p.lastCount, p.speed(), p.activeJobs.Load()
}

func (p *progress) elapsed() time.Duration {
	return time.Since(p.startTime)
}

// Active workers counter
var activeWorkers atomic.Int64

// Global print mutex for synchronized output
var printMu sync.Mutex

// printResults outputs found subdomains to stdout
func printResults(fqdn string, ips []string) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Printf("%s -> %s\n", fqdn, strings.Join(ips, ","))
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\nInterrupted, shutting down...")
		cancel()
	}()

	// Log config
	log.Println("========================================")
	log.Println("  DNS Enumeration Configuration")
	log.Println("========================================")
	log.Printf("  Domain:           %s\n", domain)
	log.Printf("  Max Length:       %d\n", maxLen)
	log.Printf("  Workers:          %d\n", workers)
	log.Printf("  Timeout:          %v\n", timeout)
	log.Printf("  Wildcard Check:   %v\n", wildcard)
	log.Printf("  Output File:      %s\n", outFileOrStdout())
	log.Printf("  Buffer Size:      %d\n", bufferSize)
	if maxCombs > 0 {
		log.Printf("  Max Combinations: %d\n", maxCombs)
	} else {
		log.Printf("  Max Combinations: (unlimited)\n")
	}
	if checkpoint != "" {
		log.Printf("  Checkpoint:       %s\n", checkpoint)
	}
	if cacheTTL > 0 {
		log.Printf("  Cache TTL:        %v\n", cacheTTL)
	}
	if noTUI {
		log.Printf("  TUI Mode:         disabled\n")
	}
	log.Println("========================================")

	// Initialize negative cache
	var negCache *negCache
	if cacheTTL > 0 {
		negCache = newNegCache(cacheTTL)
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					negCache.cleanup()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Wildcard detection
	var wildcardIPs map[string]struct{}
	if wildcard {
		wildcardIPs = detectWildcard(ctx)
		if len(wildcardIPs) > 0 {
			log.Printf("Wildcard detected! Baseline IPs: %v\n", mapKeys(wildcardIPs))
		} else {
			log.Println("No wildcard detected")
		}
	}

	// Load checkpoint if exists
	var cpData *checkpointData
	var err error
	if checkpoint != "" {
		cpData, err = loadCheckpoint(checkpoint, domain, maxLen)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("Warning: failed to load checkpoint: %v", err)
			}
		} else {
			log.Printf("Resuming from checkpoint: %d combinations completed\n", cpData.Completed)
			if len(cpData.WildcardIPs) > 0 {
				log.Printf("Restored wildcard IPs: %v\n", cpData.WildcardIPs)
				for _, ip := range cpData.WildcardIPs {
					wildcardIPs[ip] = struct{}{}
				}
			}
		}
	}

	log.Printf("Starting DNS enumeration for %s\n", domain)

	// Initialize progress tracker
	prog := newProgress()

	// Start periodic checkpoint saver
	var checkpointMu sync.Mutex
	var saveCheckpoint func(completed int64, indices []int, length int)
	if checkpoint != "" {
		saveCheckpoint = func(completed int64, indices []int, length int) {
			checkpointMu.Lock()
			defer checkpointMu.Unlock()
			data := checkpointData{
				Completed: completed,
				LastIndex: indices,
				Length:    length,
				Timestamp: time.Now(),
				MaxLen:    maxLen,
				Domain:    domain,
			}
			if len(wildcardIPs) > 0 {
				data.WildcardIPs = mapKeys(wildcardIPs)
			}
			if err := writeCheckpoint(checkpoint, &data); err != nil {
				log.Printf("Warning: failed to save checkpoint: %v", err)
			}
		}
	}

	// Initialize TUI or CLI mode
	var tuiRunner *TUIRunner
	if !noTUI {
		tuiRunner = newTUIRunner()
		tuiRunner.Start()
		time.Sleep(100 * time.Millisecond) // Give TUI time to start
	}

	// Progress update goroutine
	go func() {
		ticker := time.NewTicker(progressTick)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				completed, _, _ := prog.snapshot()
				if tuiRunner != nil && tuiRunner.IsActive() {
					_, speed, active := prog.snapshot()
					tuiRunner.SendProgress(completed, active, speed)
				} else if !noTUI {
					// CLI mode: simple counter
					if maxCombs > 0 {
						fmt.Fprintf(os.Stderr, "\r[%d/%d]", completed, maxCombs)
					} else {
						fmt.Fprintf(os.Stderr, "\r[%d]", completed)
					}
				}
			case <-ctx.Done():
				if tuiRunner != nil && tuiRunner.IsActive() {
					tuiRunner.Stop()
				}
				completed, _, _ := prog.snapshot()
				if !noTUI && (tuiRunner == nil || !tuiRunner.IsActive()) {
					fmt.Fprintf(os.Stderr, "\n[%d/%d] Done\n", completed, maxCombs)
				}
				return
			}
		}
	}()

	var wg sync.WaitGroup
	jobs := make(chan string, bufferSize)

	wg.Add(workers)
	activeWorkers.Store(int64(workers))
	for i := 0; i < workers; i++ {
		go worker(ctx, jobs, &wg, wildcardIPs, negCache, prog, tuiRunner)
	}

	generator(ctx, jobs, maxLen, maxCombs, cpData, saveCheckpoint, prog)

	close(jobs)
	wg.Wait()

	if tuiRunner != nil {
		tuiRunner.Stop()
		// Wait for TUI to fully close
		time.Sleep(200 * time.Millisecond)
	}

	// Only print Done in non-TUI mode
	if !noTUI && (tuiRunner == nil || !tuiRunner.IsActive()) {
		fmt.Fprintf(os.Stderr, "\nDNS enumeration complete.\n")
	}
}

// generator now uses strings.Builder for O(n) performance with atomic counter
func generator(ctx context.Context, jobs chan<- string, maxLen int, maxCombs int64, cp *checkpointData, saveCheckpoint func(int64, []int, int), prog *progress) {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789-"
	length := 1
	indices := make([]int, maxLen)

	// Resume from checkpoint
	if cp != nil {
		indices = cp.LastIndex
		length = cp.Length
		// Note: completed count starts from checkpoint value via generator tracking
		log.Printf("Generator resumed from length=%d, indices=%v\n", length, indices)
	}

	// Pre-allocate strings.Builder with validated size
	var sb strings.Builder
	growSize := length
	if growSize > maxGrowSize {
		growSize = maxGrowSize
	}
	sb.Grow(growSize)

	for length <= maxLen {
		if maxCombs > 0 && prog.completed.Load() >= maxCombs {
			// Save checkpoint before exiting
			if saveCheckpoint != nil {
				saveCheckpoint(prog.completed.Load(), indices, length)
			}
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		// O(n) string building using strings.Builder
		sb.Reset()
		// Adjust grow size if length increased
		if length > sb.Cap() && length <= maxGrowSize {
			sb.Grow(length)
		}
		for i := 0; i < length; i++ {
			sb.WriteByte(alphabet[indices[i]])
		}
		comb := sb.String()

		select {
		case <-ctx.Done():
			return
		case jobs <- comb:
			prog.increment()
		}

		// Periodic checkpoint save
		if saveCheckpoint != nil && prog.completed.Load()%1000 == 0 {
			saveCheckpoint(prog.completed.Load(), indices, length)
		}

		for i := length - 1; i >= 0; i-- {
			indices[i]++
			if indices[i] < len(alphabet) {
				break
			}
			indices[i] = 0
			if i == 0 {
				length++
				if length > maxLen {
					// Final checkpoint save
					if saveCheckpoint != nil {
						saveCheckpoint(prog.completed.Load(), indices, length)
					}
					return
				}
			}
		}
	}
}

func worker(ctx context.Context, jobs <-chan string, wg *sync.WaitGroup, wildcardIPs map[string]struct{}, negCache *negCache, prog *progress, tui *TUIRunner) {
	defer func() {
		activeWorkers.Add(-1)
		wg.Done()
	}()

	// Use Go native resolver (PreferGo: true, StrictErrors: false)
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
	}

	for {
		select {
		case <-ctx.Done():
			return
		case sub, ok := <-jobs:
			if !ok {
				return
			}
			prog.jobStarted()
			lookup(ctx, resolver, sub, wildcardIPs, negCache, tui)
			prog.jobFinished()
		}
	}
}

func lookup(ctx context.Context, resolver *net.Resolver, sub string, wildcardIPs map[string]struct{}, negCache *negCache, tui *TUIRunner) {
	fqdn := sub + "." + domain

	// Check negative cache first
	if negCache != nil && negCache.isCached(fqdn) {
		return
	}

	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.LookupHost(dnsCtx, fqdn)
	if err != nil {
		// Cache negative response on timeout (likely NXDOMAIN)
		if negCache != nil && errors.Is(err, context.DeadlineExceeded) {
			negCache.add(fqdn)
		}
		return
	}

	if len(ips) > 0 {
		if wildcardIPs != nil && isWildcardResponse(ips, wildcardIPs) {
			return
		}
		// Send to TUI or print to stdout
		if tui != nil && tui.IsActive() {
			tui.SendResult(fqdn, ips)
		} else {
			printResults(fqdn, ips)
		}
	}
}

func isWildcardResponse(ips []string, wildcardIPs map[string]struct{}) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if _, ok := wildcardIPs[ip]; !ok {
			return false
		}
	}
	return true
}

func detectWildcard(ctx context.Context) map[string]struct{} {
	// Use Go native resolver
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
	}

	randomSub := generateRandomSubdomain(12)
	fqdn := randomSub + "." + domain

	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.LookupHost(dnsCtx, fqdn)
	if err != nil || len(ips) == 0 {
		return nil
	}

	wildcardIPs := make(map[string]struct{})
	for _, ip := range ips {
		wildcardIPs[ip] = struct{}{}
	}

	return wildcardIPs
}

func generateRandomSubdomain(length int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789-"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		result[i] = alphabet[n.Int64()]
	}
	return string(result)
}

// loadCheckpoint reads checkpoint data from file
func loadCheckpoint(path, expectedDomain string, expectedMaxLen int) (*checkpointData, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}

	var cp checkpointData

	// Parse completed
	if n, err := parseJSONInt(string(data), "completed"); err == nil {
		cp.Completed = n
	}

	// Parse length
	if n, err := parseJSONInt(string(data), "length"); err == nil {
		cp.Length = int(n)
	}

	// Parse max_len
	if n, err := parseJSONInt(string(data), "max_len"); err == nil {
		cp.MaxLen = int(n)
	}

	// Parse domain
	if s, err := parseJSONString(string(data), "domain"); err == nil {
		cp.Domain = s
	}

	// Parse wildcard_ips
	if ips, err := parseJSONStringArray(string(data), "wildcard_ips"); err == nil {
		cp.WildcardIPs = ips
	}

	// Parse last_index array
	if indices, err := parseJSONIntArray(string(data), "last_index"); err == nil {
		cp.LastIndex = indices
	}

	// Validate checkpoint matches current config
	if cp.Domain != expectedDomain {
		return nil, fmt.Errorf("checkpoint domain mismatch: %s != %s", cp.Domain, expectedDomain)
	}
	if cp.MaxLen != expectedMaxLen {
		return nil, fmt.Errorf("checkpoint max_len mismatch: %d != %d", cp.MaxLen, expectedMaxLen)
	}

	return &cp, nil
}

// writeCheckpoint writes checkpoint atomically (temp file + rename)
func writeCheckpoint(path string, data *checkpointData) error {
	// Create temp file in same directory for atomic rename
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "checkpoint-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Write JSON directly
	fmt.Fprintf(tmp, `{"completed":%d,"last_index":%v,"length":%d,"timestamp":"%s","max_len":%d,"domain":"%s"`,
		data.Completed, intArrayToJSON(data.LastIndex), data.Length, data.Timestamp.Format(time.RFC3339),
		data.MaxLen, data.Domain)

	if len(data.WildcardIPs) > 0 {
		fmt.Fprintf(tmp, `,"wildcard_ips":%v`, data.WildcardIPs)
	}
	fmt.Fprintln(tmp, "}")

	tmp.Close()

	// Sync to disk before renaming (reduces corruption risk on crash)
	tmp.Sync()

	// Set restrictive permissions
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("set permissions: %w", err)
	}

	// Atomic rename (POSIX guarantees atomicity)
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("atomic rename: %w", err)
	}

	return nil
}

// Helper: parse JSON int field
func parseJSONInt(data, field string) (int64, error) {
	search := fmt.Sprintf(`"%s":`, field)
	idx := -1
	for i := 0; i <= len(data)-len(search); i++ {
		if data[i:i+len(search)] == search {
			idx = i + len(search)
			break
		}
	}
	if idx == -1 {
		return 0, fmt.Errorf("field not found")
	}

	start := idx
	for start < len(data) && (data[start] < '0' || data[start] > '9') && data[start] != '-' {
		start++
	}
	end := start
	for end < len(data) && data[end] >= '0' && data[end] <= '9' {
		end++
	}
	if end == start {
		return 0, fmt.Errorf("invalid number")
	}
	var n int64
	for i := start; i < end; i++ {
		n = n*10 + int64(data[i]-'0')
	}
	if start < len(data) && data[start] == '-' {
		n = -n
	}
	return n, nil
}

// Helper: parse JSON string field
func parseJSONString(data, field string) (string, error) {
	search := fmt.Sprintf(`"%s":"`, field)
	idx := -1
	for i := 0; i <= len(data)-len(search); i++ {
		if data[i:i+len(search)] == search {
			idx = i + len(search)
			break
		}
	}
	if idx == -1 {
		return "", fmt.Errorf("field not found")
	}

	end := idx
	for end < len(data) && data[end] != '"' {
		end++
	}
	if end == idx {
		return "", fmt.Errorf("invalid string")
	}
	return data[idx:end], nil
}

// Helper: parse JSON int array field
func parseJSONIntArray(data, field string) ([]int, error) {
	search := fmt.Sprintf(`"%s":[`, field)
	idx := -1
	for i := 0; i <= len(data)-len(search); i++ {
		if data[i:i+len(search)] == search {
			idx = i + len(search)
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("field not found")
	}

	var result []int
	for idx < len(data) {
		for idx < len(data) && (data[idx] == ' ' || data[idx] == '\t' || data[idx] == ',' || data[idx] == '\n') {
			idx++
		}
		if idx >= len(data) || data[idx] == ']' {
			break
		}

		start := idx
		for start < len(data) && (data[start] < '0' || data[start] > '9') {
			start++
		}
		end := start
		for end < len(data) && data[end] >= '0' && data[end] <= '9' {
			end++
		}
		if end == start {
			break
		}
		var n int
		for i := start; i < end; i++ {
			n = n*10 + int(data[i]-'0')
		}
		result = append(result, n)
		idx = end
	}
	return result, nil
}

// Helper: parse JSON string array field
func parseJSONStringArray(data, field string) ([]string, error) {
	search := fmt.Sprintf(`"%s":["`, field)
	idx := -1
	for i := 0; i <= len(data)-len(search); i++ {
		if data[i:i+len(search)] == search {
			idx = i + len(search)
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("field not found")
	}

	var result []string
	for idx < len(data) {
		for idx < len(data) && (data[idx] == ' ' || data[idx] == '\t' || data[idx] == ',' || data[idx] == '\n') {
			idx++
		}
		if idx >= len(data) || data[idx] == ']' {
			break
		}

		if data[idx] == '"' {
			idx++
		}

		start := idx
		for idx < len(data) && data[idx] != '"' {
			idx++
		}
		if idx > start {
			result = append(result, data[start:idx])
		}
		idx++
	}
	return result, nil
}

// Helper: convert int slice to JSON array string
func intArrayToJSON(arr []int) string {
	if len(arr) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, n := range arr {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf("%d", n))
	}
	sb.WriteByte(']')
	return sb.String()
}

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func outFileOrStdout() string {
	if outFile == "" {
		return "(stdout)"
	}
	return outFile
}
