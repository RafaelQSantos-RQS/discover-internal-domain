package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CheckpointData holds persistent checkpoint state.
type CheckpointData struct {
	Completed   int64     `json:"completed"`
	LastIndex   []int     `json:"last_index"`
	Length      int       `json:"length"`
	Timestamp   time.Time `json:"timestamp"`
	MaxLen      int       `json:"max_len"`
	Domain      string    `json:"domain"`
	WildcardIPs []string  `json:"wildcard_ips,omitempty"`
}

// LoadCheckpoint reads checkpoint data from a file.
func LoadCheckpoint(path, expectedDomain string, expectedMaxLen int) (*CheckpointData, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}

	var cp CheckpointData
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parse checkpoint: %w", err)
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

// SaveCheckpoint writes checkpoint data atomically (temp file + rename).
func SaveCheckpoint(path string, data *CheckpointData) error {
	// Create temp file in same directory for atomic rename
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "checkpoint-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Write JSON
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "")
	if err := enc.Encode(data); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	tmp.Close()

	// Sync to disk before renaming
	if err := tmp.Sync(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("sync: %w", err)
	}

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

// CreateCheckpointData creates a checkpoint data structure.
func CreateCheckpointData(completed int64, indices []int, length, maxLen int, domain string, wildcardIPs []string) *CheckpointData {
	return &CheckpointData{
		Completed:   completed,
		LastIndex:   indices,
		Length:      length,
		Timestamp:   time.Now(),
		MaxLen:      maxLen,
		Domain:      domain,
		WildcardIPs: wildcardIPs,
	}
}

// ToGeneratorCheckpoint converts to generator checkpoint format.
func (cp *CheckpointData) ToGeneratorCheckpoint() *Checkpoint {
	return &Checkpoint{
		Completed: cp.Completed,
		LastIndex: cp.LastIndex,
		Length:    cp.Length,
	}
}

// FormatWildcardIPs formats wildcard IPs for logging.
func FormatWildcardIPs(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	sorted := make([]string, len(ips))
	copy(sorted, ips)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}
