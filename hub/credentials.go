package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// CredentialStore persists the Hub's view of provider credentials: the opaque
// envelopes provider agents register on dial-in. It holds ciphertext only — an
// envelope sealed to the TEE's inbox key — so the Hub can forward it onto every
// job it dispatches without ever learning the token inside.
//
// A credential exists in the store exactly while its agent is online: the gate
// Puts on registration and Deletes on disconnect. It is the "hub db" that
// decouples a job from the live registration that produced it — by the time an
// Execute runs, the agent that sealed the token may have moved on, but the
// envelope it left behind is all the TEE needs.
type CredentialStore interface {
	// Put stores the provider's envelope, replacing any previous one.
	Put(provider string, envelope tee.Envelope) error
	// Get returns the provider's current envelope.
	Get(provider string) (tee.Envelope, bool)
	// Delete removes the provider's envelope, e.g. when its agent disconnects.
	Delete(provider string) error
}

// MemoryCredentialStore is an in-memory CredentialStore. It is the default
// backing when a Hub is built without one, and the natural store for one-shot
// tools whose credential lives only for the duration of the process.
type MemoryCredentialStore struct {
	mu        sync.RWMutex
	envelopes map[string]tee.Envelope
}

// NewMemoryCredentialStore returns an empty in-memory store.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{envelopes: make(map[string]tee.Envelope)}
}

// Put implements CredentialStore.
func (s *MemoryCredentialStore) Put(provider string, envelope tee.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envelopes[provider] = envelope
	return nil
}

// Get implements CredentialStore.
func (s *MemoryCredentialStore) Get(provider string) (tee.Envelope, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	env, ok := s.envelopes[provider]
	return env, ok
}

// Delete implements CredentialStore.
func (s *MemoryCredentialStore) Delete(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.envelopes, provider)
	return nil
}

// FileCredentialStore is a CredentialStore backed by one JSON file per
// provider under a directory. It is the durable "hub db" a resident Hub uses:
// envelopes survive a Hub restart, so a newly booted Hub can still settle
// against the tokens registered before it went down (they are re-sealed by the
// next agent dial anyway).
type FileCredentialStore struct {
	dir string
	mu  sync.Mutex
}

// NewFileCredentialStore creates a file-backed store rooted at dir.
func NewFileCredentialStore(dir string) *FileCredentialStore {
	return &FileCredentialStore{dir: dir}
}

// Put implements CredentialStore.
func (s *FileCredentialStore) Put(provider string, envelope tee.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, provider+".json"), b, 0o600)
}

// Get implements CredentialStore.
func (s *FileCredentialStore) Get(provider string) (tee.Envelope, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, provider+".json"))
	if err != nil {
		return tee.Envelope{}, false
	}
	var env tee.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return tee.Envelope{}, false
	}
	return env, true
}

// Delete implements CredentialStore.
func (s *FileCredentialStore) Delete(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(filepath.Join(s.dir, provider+".json"))
}
