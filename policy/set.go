package policy

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// ErrPolicyRollback means an update tried to replace a policy with an older
// one. Rollbacks are refused because an expired, over-permissive policy is
// precisely what an attacker would replay once a provider has tightened it.
var ErrPolicyRollback = errors.New("policy update is older than the installed policy")

// Set holds the active policy for each provider.
//
// A set only ever contains verified policies: Add verifies the signature before
// installing, so a policy that reaches Authorize cannot have been tampered with
// in transit or forged by the Hub. That property is what lets the TEE treat the
// set as trusted input despite it arriving over an untrusted channel.
type Set struct {
	mu       sync.RWMutex
	policies map[string]SignedPolicy
}

// NewSet returns an empty policy set.
func NewSet() *Set {
	return &Set{policies: make(map[string]SignedPolicy)}
}

// Add verifies a signed policy and installs it for its provider.
//
// A provider can be updated — credentials are rotated and scopes change — but
// the replacement must be issued at or after the policy it replaces.
func (s *Set) Add(signed SignedPolicy, now time.Time) error {
	if err := VerifySignedPolicy(signed, now); err != nil {
		return err
	}

	provider := signed.Policy.Provider
	if provider == "" {
		return errors.New("policy has no provider")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.policies[provider]; ok && signed.Policy.IssuedAt < current.Policy.IssuedAt {
		return fmt.Errorf("%w: incoming %d, installed %d",
			ErrPolicyRollback, signed.Policy.IssuedAt, current.Policy.IssuedAt)
	}
	s.policies[provider] = signed
	return nil
}

// Load verifies and installs a batch of policies. It installs all of them or
// none: a partial policy set would leave some providers silently unserviceable,
// and a half-applied update is harder to reason about than a failed one.
func (s *Set) Load(signed []SignedPolicy, now time.Time) error {
	staged := make(map[string]SignedPolicy, len(signed))
	for _, entry := range signed {
		if err := VerifySignedPolicy(entry, now); err != nil {
			return err
		}
		staged[entry.Policy.Provider] = entry
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for provider, entry := range staged {
		if current, ok := s.policies[provider]; ok && entry.Policy.IssuedAt < current.Policy.IssuedAt {
			return fmt.Errorf("%w: %q incoming %d, installed %d",
				ErrPolicyRollback, provider, entry.Policy.IssuedAt, current.Policy.IssuedAt)
		}
	}
	for provider, entry := range staged {
		s.policies[provider] = entry
	}
	return nil
}

// Remove drops the policy for a provider, immediately denying its jobs.
func (s *Set) Remove(provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, provider)
}

// Get returns a copy of the installed policy for a provider.
func (s *Set) Get(provider string) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	signed, ok := s.policies[provider]
	if !ok {
		return Policy{}, false
	}
	return signed.Policy, true
}

// Providers returns the installed provider names in sorted order.
func (s *Set) Providers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	providers := make([]string, 0, len(s.policies))
	for provider := range s.policies {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

// Len returns the number of installed policies.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.policies)
}

// Authorize resolves the job's provider and checks the spec against its policy.
func (s *Set) Authorize(spec jobs.Spec) (Decision, error) {
	s.mu.RLock()
	signed, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return signed.Policy.Authorize(spec)
}

// AuthorizeAt is Authorize plus both validity windows.
func (s *Set) AuthorizeAt(spec jobs.Spec, now time.Time) (Decision, error) {
	s.mu.RLock()
	signed, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return signed.Policy.AuthorizeAt(spec, now)
}
