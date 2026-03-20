package core

import (
	"context"
	"net"
	"sync"
	"time"
)

// WorkerPool manages a pool of DNS lookup workers.
type WorkerPool struct {
	workers int
	timeout time.Duration
}

// NewWorkerPool creates a new worker pool configuration.
func NewWorkerPool(workers int, timeout time.Duration) *WorkerPool {
	return &WorkerPool{
		workers: workers,
		timeout: timeout,
	}
}

// Run starts the worker pool and processes jobs until the context is cancelled
// or the jobs channel is closed. Results are written to the state store.
func (wp *WorkerPool) Run(
	ctx context.Context,
	jobs <-chan string,
	domain string,
	wildcardDetector *WildcardDetector,
	negCache *NegCache,
	onResult func(fqdn string, ips []string),
	onJobFinished func(),
) {
	var wg sync.WaitGroup

	wg.Add(wp.workers)
	for i := 0; i < wp.workers; i++ {
		go wp.worker(ctx, &wg, jobs, domain, wildcardDetector, negCache, onResult, onJobFinished)
	}

	wg.Wait()
}

// worker is a single DNS lookup worker goroutine.
func (wp *WorkerPool) worker(
	ctx context.Context,
	wg *sync.WaitGroup,
	jobs <-chan string,
	domain string,
	wildcardDetector *WildcardDetector,
	negCache *NegCache,
	onResult func(fqdn string, ips []string),
	onJobFinished func(),
) {
	defer wg.Done()

	// Create a resolver per worker (not shared)
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
			Lookup(ctx, resolver, sub, domain, wildcardDetector, negCache, wp.timeout, onResult)
			if onJobFinished != nil {
				onJobFinished()
			}
		}
	}
}
