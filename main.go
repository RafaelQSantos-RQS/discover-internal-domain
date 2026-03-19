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
	"syscall"
	"time"

	"github.com/spf13/pflag"
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

// Negative cache for NXDOMAIN responses
type negCache struct {
	mu    sync.RWMutex
	cache map[string]time.Time
	ttl   time.Duration
}

func newNegCache(ttl time.Duration) *negCache {
	return &negCache{
		cache: make(map[string]time.Time),
		ttl:   ttl,
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
	nc.cache[fqdn] = time.Now().Add(nc.ttl)
}

func (nc *negCache) cleanup() {
	if nc.ttl == 0 {
		return
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()
	now := time.Now()
	for fqdn, expire := range nc.cache {
		if now.After(expire) {
			delete(nc.cache, fqdn)
		}
	}
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

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Interrupted, shutting down...")
		cancel()
	}()

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

	var wg sync.WaitGroup
	jobs := make(chan string, bufferSize)

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker(ctx, jobs, &wg, wildcardIPs, negCache)
	}

	generator(ctx, jobs, maxLen, maxCombs, cpData, saveCheckpoint)

	close(jobs)
	wg.Wait()

	// Final checkpoint save on completion
	if checkpoint != "" {
		// Get final state from generator context
		// This is already handled in generator on maxCombs/maxLen completion
	}

	log.Println("Done")
}

// generator now uses strings.Builder for O(n) performance
func generator(ctx context.Context, jobs chan<- string, maxLen int, maxCombs int64, cp *checkpointData, saveCheckpoint func(int64, []int, int)) {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789-"
	length := 1
	indices := make([]int, maxLen)
	generated := int64(0)

	// Resume from checkpoint
	if cp != nil {
		indices = cp.LastIndex
		length = cp.Length
		generated = cp.Completed
		log.Printf("Generator resumed from length=%d, indices=%v, completed=%d\n", length, indices, generated)
	}

	// Pre-allocate strings.Builder for efficiency
	var sb strings.Builder
	sb.Grow(maxLen) // Pre-allocate capacity

	for length <= maxLen {
		if maxCombs > 0 && generated >= maxCombs {
			// Save checkpoint before exiting
			if saveCheckpoint != nil {
				saveCheckpoint(generated, indices, length)
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
		for i := 0; i < length; i++ {
			sb.WriteByte(alphabet[indices[i]])
		}
		comb := sb.String()

		select {
		case <-ctx.Done():
			return
		case jobs <- comb:
		}
		generated++

		// Periodic checkpoint save
		if saveCheckpoint != nil && generated%1000 == 0 {
			saveCheckpoint(generated, indices, length)
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
						saveCheckpoint(generated, indices, length)
					}
					return
				}
			}
		}
	}
}

func worker(ctx context.Context, jobs <-chan string, wg *sync.WaitGroup, wildcardIPs map[string]struct{}, negCache *negCache) {
	defer wg.Done()

	resolver := &net.Resolver{
		PreferGo: true,
	}

	for {
		select {
		case <-ctx.Done():
			return
		case sub, ok := <-jobs:
			if !ok {
				return
			}
			lookup(ctx, resolver, sub, wildcardIPs, negCache)
		}
	}
}

func lookup(ctx context.Context, resolver *net.Resolver, sub string, wildcardIPs map[string]struct{}, negCache *negCache) {
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
		fmt.Printf("%s -> %s\n", fqdn, strings.Join(ips, ","))
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
	resolver := &net.Resolver{
		PreferGo: true,
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

	// Simple JSON parsing without external dependency
	// Format: {"completed":N,"last_index":[...],"length":N,"timestamp":"..."}
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

	// Set restrictive permissions
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("set permissions: %w", err)
	}

	// Atomic rename
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

	// Read number
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

	// Read string until closing quote
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
		// Skip whitespace and commas
		for idx < len(data) && (data[idx] == ' ' || data[idx] == '\t' || data[idx] == ',' || data[idx] == '\n') {
			idx++
		}
		if idx >= len(data) || data[idx] == ']' {
			break
		}

		// Read number
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
		// Skip whitespace
		for idx < len(data) && (data[idx] == ' ' || data[idx] == '\t' || data[idx] == ',' || data[idx] == '\n') {
			idx++
		}
		if idx >= len(data) || data[idx] == ']' {
			break
		}

		// Skip opening quote
		if data[idx] == '"' {
			idx++
		}

		// Read string until closing quote
		start := idx
		for idx < len(data) && data[idx] != '"' {
			idx++
		}
		if idx > start {
			result = append(result, data[start:idx])
		}
		idx++ // Skip closing quote
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
