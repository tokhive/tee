package tee

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrNoSeqStore means the service was built without a sequence store.
//
// It is a wiring error, deliberately not defaulted. A silent in-memory
// fallback would be worse than a refusal: the counter would reset on every
// restart, receipts would repeat sequence numbers, and a provider auditing for
// hidden receipts would compare an incoherent series and conclude nothing is
// missing. The one failure mode ProviderSeq exists to catch would be the one
// it silently stopped catching. Volatile storage therefore has to be asked for
// by name — see NewMemorySeqStore.
var ErrNoSeqStore = errors.New("no sequence store configured")

// SeqStore assigns and tracks the per-provider monotonic sequence number the
// TEE signs into every receipt (proof.Receipt.ProviderSeq).
//
// This is the only stateful component in the enclave. The interface is kept
// this small so the production backend (a blob sealed under the platform
// sealing key) and the development backend (a plain file) are interchangeable
// without the execution path knowing which one it has.
//
// A provider that has never been used starts at zero, so the first number
// issued is 1. Implementations must be safe for concurrent use and must not
// return a number they have not yet durably recorded: a sequence number that
// survives in a receipt but not in the store would be reissued after a
// restart, and two different receipts bearing the same number destroy the
// audit property.
type SeqStore interface {
	// Next advances providerID's counter and returns the new value.
	Next(providerID []byte) (uint64, error)

	// Peek returns the current value without advancing it. It exists for
	// operators and for startup logging — "resuming provider X at N" is how a
	// deployment confirms its counters actually survived a restart.
	Peek(providerID []byte) (uint64, error)

	// Close flushes and releases resources.
	Close() error
}

// memorySeqStore keeps counters in process memory only.
type memorySeqStore struct {
	mu   sync.Mutex
	data map[string]uint64
}

// NewMemorySeqStore returns a volatile sequence store.
//
// Counters are lost when the process exits, which breaks the cross-restart
// guarantee ProviderSeq is for. That makes it correct for exactly two uses:
// unit tests, and the in-memory fake TEE that Hub business tests run against.
// It must never back a TEE that issues receipts a provider will settle
// against.
func NewMemorySeqStore() SeqStore {
	return &memorySeqStore{data: make(map[string]uint64)}
}

func (s *memorySeqStore) Next(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[string(providerID)]++
	return s.data[string(providerID)], nil
}

func (s *memorySeqStore) Peek(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[string(providerID)], nil
}

func (s *memorySeqStore) Close() error { return nil }

// fileSeqStore persists counters to one JSON file.
type fileSeqStore struct {
	mu   sync.Mutex
	path string
	data map[string]uint64
}

// NewFileSeqStore opens, or initialises, a file-backed sequence store.
//
// It is the development and simulation backend: the counters genuinely survive
// process restarts, which is what makes gap detection testable on a laptop,
// and it pulls in no cryptography. The production backend seals the same map
// under the platform sealing key; only the constructor changes.
func NewFileSeqStore(path string) (SeqStore, error) {
	s := &fileSeqStore{path: path, data: make(map[string]uint64)}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("seqstore: create dir: %w", err)
	}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.data); err != nil {
				// Refuse rather than start from zero. An unreadable counter
				// file is indistinguishable from a tampered one, and both
				// mean the next number issued would be a repeat.
				return nil, fmt.Errorf("seqstore: parse %s: %w", path, err)
			}
		}
	case os.IsNotExist(err):
		// First run.
	default:
		return nil, fmt.Errorf("seqstore: read %s: %w", path, err)
	}
	return s, nil
}

// Next persists the increment before returning it, so a number handed to a
// receipt has already been recorded. The rollback on write failure keeps the
// in-memory map consistent with the file rather than drifting one ahead.
func (s *fileSeqStore) Next(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(providerID)
	s.data[key]++
	if err := s.flushLocked(); err != nil {
		s.data[key]--
		return 0, err
	}
	return s.data[key], nil
}

func (s *fileSeqStore) Peek(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[string(providerID)], nil
}

func (s *fileSeqStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

// flushLocked writes through a temporary file and renames it, so a crash
// mid-write leaves the previous counters intact instead of a truncated file
// the next start would refuse to parse.
func (s *fileSeqStore) flushLocked() error {
	encoded, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("seqstore: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return fmt.Errorf("seqstore: write: %w", err)
	}
	return os.Rename(tmp, s.path)
}
