package tee

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrCredentialUnavailable means no credential is loaded for a provider, so the
// job cannot be executed. It is distinct from a policy refusal: the policy
// admitted the request, the TEE simply has nothing to authenticate it with.
var ErrCredentialUnavailable = errors.New("no credential available for provider")

// CredentialSource resolves the secret for a provider.
//
// The secret is the one value in the system that must never leave the enclave.
// It is deliberately not part of the policy (which is signed, distributed,
// and logged) and not part of the receipt (which is published). This interface
// exists so that the storage behind it — an in-memory map today, a sealed
// vault later — can change without the execution path noticing.
type CredentialSource interface {
	// Credential returns the secret for a provider. The second return value is
	// false when the provider has no credential loaded.
	Credential(ctx context.Context, provider string) (string, bool)
}

// StaticCredentials is an in-memory credential store.
//
// It is the first-version implementation: the TEE is provisioned with the
// secrets it needs and they live only in its memory. A production deployment
// should replace it with something that unseals from the platform's sealing
// key, but the shape of the interface is the same.
type StaticCredentials struct {
	mu    sync.RWMutex
	store map[string]string
}

// NewStaticCredentials returns an empty in-memory store.
func NewStaticCredentials() *StaticCredentials {
	return &StaticCredentials{store: make(map[string]string)}
}

// Set installs or replaces a provider's credential.
func (s *StaticCredentials) Set(provider, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[provider] = secret
}

// Remove drops a provider's credential, immediately making its jobs
// unexecutable.
func (s *StaticCredentials) Remove(provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, provider)
}

// Credential returns the secret for a provider.
func (s *StaticCredentials) Credential(_ context.Context, provider string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, ok := s.store[provider]
	return secret, ok
}

// missingCredential is the error returned when a provider has no secret loaded
// and the job therefore cannot be executed.
func missingCredential(provider string) error {
	return fmt.Errorf("%w: %q", ErrCredentialUnavailable, provider)
}
