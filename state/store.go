// Package state provides a centralized, thread-safe store for DNS enumeration state.
// This eliminates the need for push-based communication between workers and the TUI,
// allowing the BubbleTea model to pull updates on its own schedule.
package state

import (
	"sync"
	"sync/atomic"
	"time"
)

// Result represents a discovered DNS entry.
type Result struct {
	FQDN string
	IPs  []string
}

// Store is the centralized thread-safe state for DNS enumeration.
// Workers write results here; the TUI reads from here on tick intervals.
type Store struct {
	// Immutable counters (atomic)
	completed  atomic.Int64
	activeJobs atomic.Int64

	// Speed calculation protected by mutex
	speedMu      sync.RWMutex
	lastCount    int64
	lastTime     time.Time
	currentSpeed float64

	// Results buffer (bounded, circular)
	resultsMu  sync.Mutex
	results    []Result
	maxResults int

	// State flags (atomic.Bool not available in older Go, use int32)
	running int32 // 1 = running, 0 = stopped

	// Timing
	startTime time.Time

	// Total expected (may be 0 for unlimited)
	total int64
}

// NewStore creates a new state store.
func NewStore(total int64, maxResults int) *Store {
	if maxResults <= 0 {
		maxResults = 100
	}
	return &Store{
		lastTime:   time.Now(),
		startTime:  time.Now(),
		maxResults: maxResults,
		total:      total,
	}
}

// JobStarted increments the active job counter.
func (s *Store) JobStarted() {
	s.activeJobs.Add(1)
}

// JobFinished decrements the active job counter.
func (s *Store) JobFinished() {
	s.activeJobs.Add(-1)
}

// AddCompleted increments the completed counter and recalculates speed.
func (s *Store) AddCompleted() {
	s.completed.Add(1)
}

// AddResult adds a result to the bounded circular buffer.
// Thread-safe.
func (s *Store) AddResult(fqdn string, ips []string) {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	// Prepend to maintain "most recent first" ordering
	s.results = append([]Result{{FQDN: fqdn, IPs: ips}}, s.results...)

	// Trim to max size
	if len(s.results) > s.maxResults {
		s.results = s.results[:s.maxResults]
	}
}

// Snapshot returns a consistent read of all state values.
// This is the primary method for TUI to read state safely.
func (s *Store) Snapshot() (completed, active int64, speed float64, total int64, elapsed time.Duration) {
	now := time.Now()

	// Recalculate speed with write lock (only writer updates lastCount/lastTime)
	s.speedMu.Lock()
	elapsedSeconds := now.Sub(s.lastTime).Seconds()

	if elapsedSeconds >= 0.1 {
		current := s.completed.Load()
		s.currentSpeed = float64(current-s.lastCount) / elapsedSeconds
		s.lastCount = current
		s.lastTime = now
	}
	speed = s.currentSpeed
	s.speedMu.Unlock()

	// Read counters (atomic, no lock needed)
	completed = s.completed.Load()
	active = s.activeJobs.Load()
	total = s.total
	elapsed = now.Sub(s.startTime)

	return
}

// Results returns a copy of the current results.
// Thread-safe copy to avoid concurrent read/write issues.
func (s *Store) Results() []Result {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()

	// Return a copy to prevent external mutation
	result := make([]Result, len(s.results))
	copy(result, s.results)
	return result
}

// ResultsCount returns the number of results discovered.
func (s *Store) ResultsCount() int {
	s.resultsMu.Lock()
	defer s.resultsMu.Unlock()
	return len(s.results)
}

// SetRunning atomically sets the running flag.
func (s *Store) SetRunning(running bool) {
	var val int32
	if running {
		val = 1
	}
	atomic.StoreInt32(&s.running, val)
}

// IsRunning atomically reads the running flag.
func (s *Store) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

// StartTime returns when the enumeration started.
func (s *Store) StartTime() time.Time {
	return s.startTime
}
