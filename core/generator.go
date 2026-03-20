package core

import (
	"context"
	"strings"
	"sync/atomic"
)

const (
	maxMaxLen   = 63             // DNS label max length
	maxGrowSize = maxMaxLen + 10 // Max size for strings.Builder.Grow()
)

// Generator produces subdomain combinations.
type Generator struct {
	alphabet string
	maxLen   int
	maxCombs int64
}

// NewGenerator creates a new combination generator.
func NewGenerator(maxLen int, maxCombs int64) *Generator {
	if maxLen > maxMaxLen {
		maxLen = maxMaxLen
	}
	return &Generator{
		alphabet: "abcdefghijklmnopqrstuvwxyz0123456789-",
		maxLen:   maxLen,
		maxCombs: maxCombs,
	}
}

// Checkpoint holds generator state for resumption.
type Checkpoint struct {
	Completed int64
	LastIndex []int
	Length    int
}

// Run generates combinations and sends them to the jobs channel.
// It respects the context for cancellation and tracks progress via atomic counter.
func (g *Generator) Run(ctx context.Context, jobs chan<- string, completed *atomic.Int64, checkpoint *Checkpoint) error {
	indices := make([]int, g.maxLen)

	// Resume from checkpoint if provided
	if checkpoint != nil {
		indices = checkpoint.LastIndex
	}

	// Pre-allocate strings.Builder
	var sb strings.Builder
	initialLen := 1
	if checkpoint != nil {
		initialLen = checkpoint.Length
	}
	sb.Grow(initialLen)

	length := 1
	if checkpoint != nil {
		length = checkpoint.Length
	}

	for length <= g.maxLen {
		// Check if we've hit the max combinations limit
		if g.maxCombs > 0 && completed.Load() >= g.maxCombs {
			return nil
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Build the combination string
		sb.Reset()
		if length > sb.Cap() && length <= maxGrowSize {
			sb.Grow(length)
		}
		for i := 0; i < length; i++ {
			sb.WriteByte(g.alphabet[indices[i]])
		}
		comb := sb.String()

		// Send to jobs channel (blocking send)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case jobs <- comb:
			completed.Add(1)
		}

		// Advance to next combination
		for i := length - 1; i >= 0; i-- {
			indices[i]++
			if indices[i] < len(g.alphabet) {
				break
			}
			indices[i] = 0
			if i == 0 {
				// Carry to next length
				length++
				if length > g.maxLen {
					return nil
				}
			}
		}
	}

	return nil
}

// SaveCheckpoint creates a checkpoint snapshot for the current state.
func (g *Generator) SaveCheckpoint(completed int64, indices []int, length int) *Checkpoint {
	return &Checkpoint{
		Completed: completed,
		LastIndex: indices,
		Length:    length,
	}
}
