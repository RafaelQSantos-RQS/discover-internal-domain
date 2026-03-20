package core

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RafaelQSantos-RQS/discover-internal-domain/state"
)

// Orchestrator manages the entire DNS enumeration process.
type Orchestrator struct {
	domain         string
	workers        int
	timeout        time.Duration
	maxCombs       int64
	maxLen         int
	bufferSize     int
	cacheTTL       time.Duration
	checkpointPath string
	checkpointData *CheckpointData
	wildcardIPs    []string

	// Components (initialized in Run)
	negCache         *NegCache
	wildcardDetector *WildcardDetector
	store            *state.Store
	generator        *Generator
	workerPool       *WorkerPool
}

// Config holds orchestrator configuration.
type Config struct {
	Domain          string
	Workers         int
	Timeout         time.Duration
	MaxCombinations int64
	MaxLen          int
	BufferSize      int
	CacheTTL        time.Duration
	CheckpointPath  string
	CheckpointData  *CheckpointData
	WildcardIPs     []string // Pre-detected wildcard IPs (from checkpoint)
}

// NewOrchestrator creates a new orchestrator.
func NewOrchestrator(cfg Config) *Orchestrator {
	return &Orchestrator{
		domain:         cfg.Domain,
		workers:        cfg.Workers,
		timeout:        cfg.Timeout,
		maxCombs:       cfg.MaxCombinations,
		maxLen:         cfg.MaxLen,
		bufferSize:     cfg.BufferSize,
		cacheTTL:       cfg.CacheTTL,
		checkpointPath: cfg.CheckpointPath,
		checkpointData: cfg.CheckpointData,
		wildcardIPs:    cfg.WildcardIPs,
	}
}

// Run executes the DNS enumeration process.
// onResult is called for each discovered subdomain.
// onProgress is called periodically with current stats.
// onDone is called when enumeration completes.
// It blocks until enumeration completes or context is cancelled.
func (o *Orchestrator) Run(
	ctx context.Context,
	onResult func(fqdn string, ips []string),
	onProgress func(completed, active int64, speed float64, total int64),
	onDone func(completed int64, elapsed time.Duration),
	progressInterval time.Duration,
) error {
	// Initialize negative cache
	if o.cacheTTL > 0 {
		o.negCache = NewNegCache(o.cacheTTL)
		go o.cacheCleanupRoutine(ctx)
	}

	// Initialize state store
	o.store = state.NewStore(o.maxCombs, 100)
	o.store.SetRunning(true)
	defer o.store.SetRunning(false)

	// Initialize wildcard detector
	o.wildcardDetector = &WildcardDetector{}
	if len(o.wildcardIPs) > 0 {
		ipSet := make(map[string]struct{})
		for _, ip := range o.wildcardIPs {
			ipSet[ip] = struct{}{}
		}
		o.wildcardDetector.ips = ipSet
	}

	// Initialize components
	o.generator = NewGenerator(o.maxLen, o.maxCombs)
	o.workerPool = NewWorkerPool(o.workers, o.timeout)

	// Progress tracking
	var checkpointMu sync.Mutex
	var checkpointMuPtr = &checkpointMu
	completed := atomic.Int64{}
	if o.checkpointData != nil {
		completed.Store(o.checkpointData.Completed)
	}

	// Create jobs channel
	jobs := make(chan string, o.bufferSize)

	// Create done channel for progress reporter
	progressDone := make(chan struct{})

	// Start progress reporter
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.progressReporter(ctx, jobs, &completed, onProgress, progressInterval, progressDone)
	}()

	// Start checkpoint saver if configured
	if o.checkpointPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o.checkpointRoutine(ctx, jobs, &completed, checkpointMuPtr)
		}()
	}

	// Create checkpoint for generator
	var genCheckpoint *Checkpoint
	if o.checkpointData != nil {
		genCheckpoint = o.checkpointData.ToGeneratorCheckpoint()
	}

	// Create callback that updates state store and calls onResult
	onResultWrapper := func(fqdn string, ips []string) {
		o.store.AddResult(fqdn, ips)
		onResult(fqdn, ips)
	}

	// Callback for job completion tracking
	onJobFinished := func() {
		o.store.AddCompleted()
	}

	// Run workers (they will block waiting for jobs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.workerPool.Run(ctx, jobs, o.domain, o.wildcardDetector, o.negCache, onResultWrapper, onJobFinished)
	}()

	// Run generator (sends jobs to channel)
	if err := o.generator.Run(ctx, jobs, &completed, genCheckpoint); err != nil {
		log.Printf("Generator error: %v", err)
	}

	// Close jobs when generator is done
	close(jobs)

	// Wait for reporters
	wg.Wait()

	// Signal completion
	o.store.SetRunning(false)
	if onDone != nil {
		onDone(completed.Load(), time.Since(o.store.StartTime()))
	}

	return nil
}

// progressReporter periodically reports progress.
func (o *Orchestrator) progressReporter(
	ctx context.Context,
	jobs <-chan string,
	completed *atomic.Int64,
	callback func(completed, active int64, speed float64, total int64),
	interval time.Duration,
	done chan<- struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			comp, active, speed, total, _ := o.store.Snapshot()
			callback(comp, active, speed, total)

			// Check if enumeration is complete (no more active jobs and channel empty)
			if active == 0 && comp > 0 && len(jobs) == 0 {
				close(done)
				return
			}
		}
	}
}

// checkpointRoutine periodically saves checkpoints.
func (o *Orchestrator) checkpointRoutine(ctx context.Context, jobs <-chan string, completed *atomic.Int64, mu *sync.Mutex) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final checkpoint save
			mu.Lock()
			o.saveCheckpoint(completed.Load())
			mu.Unlock()
			return
		case <-ticker.C:
			if len(jobs) == 0 && completed.Load() > 0 {
				mu.Lock()
				o.saveCheckpoint(completed.Load())
				mu.Unlock()
			}
		}
	}
}

// saveCheckpoint saves a checkpoint to disk.
func (o *Orchestrator) saveCheckpoint(completed int64) {
	data := CreateCheckpointData(
		completed,
		nil, // We don't track indices outside generator
		0,
		o.maxLen,
		o.domain,
		nil,
	)
	if err := SaveCheckpoint(o.checkpointPath, data); err != nil {
		log.Printf("Warning: failed to save checkpoint: %v", err)
	}
}

// cacheCleanupRoutine periodically cleans expired entries from the cache.
func (o *Orchestrator) cacheCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.negCache.Cleanup()
		}
	}
}

// Store returns the state store (for TUI access).
func (o *Orchestrator) Store() *state.Store {
	return o.store
}

// Domain returns the target domain.
func (o *Orchestrator) Domain() string {
	return o.domain
}
