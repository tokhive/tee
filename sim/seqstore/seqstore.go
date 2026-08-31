// Package seqstore implements the per-provider monotonic sequence counter that
// the TEE signs into every execution receipt (proof.Receipt.ProviderSeq).
//
// It is the only piece of TEE state. The interface is deliberately tiny so the
// production backend (a sealed blob under the platform sealing key) and the
// simulation backend (a plain file) are interchangeable without touching TEE
// logic.
package seqstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SeqStore assigns and tracks monotonic sequence numbers per provider.
//
// Next returns the next number for a provider and persists the increment
// atomically; Peek returns the current maximum without changing it. A missing
// provider starts at zero, so the first issued number is 1.
type SeqStore interface {
	// Next returns the next sequence number for providerID and advances it.
	Next(providerID []byte) (uint64, error)
	// Peek returns the current maximum sequence number without advancing.
	Peek(providerID []byte) (uint64, error)
	// Close flushes and releases any resources.
	Close() error
}

// fileStore is the simulation backend. It keeps one JSON file of per-provider
// counters and serialises access with a mutex, so a TEE process serving
// concurrent requests stays correct and the counters survive restarts — which
// is exactly what lets the harness assert "seq keeps climbing after TEE
// restart".
type fileStore struct {
	mu   sync.Mutex
	path string
	data map[string]uint64
}

// NewFileStore opens (or initialises) a file-backed sequence store at path.
func NewFileStore(path string) (SeqStore, error) {
	s := &fileStore{
		path: path,
		data: make(map[string]uint64),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("seqstore: create dir: %w", err)
	}
	if b, err := os.ReadFile(path); err == nil {
		if len(b) > 0 {
			if err := json.Unmarshal(b, &s.data); err != nil {
				return nil, fmt.Errorf("seqstore: parse %s: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("seqstore: read %s: %w", path, err)
	}
	return s, nil
}

func key(providerID []byte) string { return string(providerID) }

func (s *fileStore) Next(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(providerID)
	s.data[k]++
	if err := s.flushLocked(); err != nil {
		s.data[k]-- // roll back on persistence failure
		return 0, err
	}
	return s.data[k], nil
}

func (s *fileStore) Peek(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[key(providerID)], nil
}

func (s *fileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *fileStore) flushLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("seqstore: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("seqstore: write: %w", err)
	}
	return os.Rename(tmp, s.path)
}
