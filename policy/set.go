package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// PolicySetHashDomain separates the policy-set digest from every other hash in
// the TokenHive stack. It is the value a TEE binds into its attestation
// measurement so a verifier can confirm which whitelist configuration the
// enclave was deployed with.
const PolicySetHashDomain = "TokenHive.PolicySet.v1"

// ErrPolicyRollback means an update tried to replace a policy with an older
// one. Rollbacks are refused because an expired, over-permissive policy is
// precisely what an attacker would replay once an operator has tightened it.
var ErrPolicyRollback = errors.New("policy update is older than the installed policy")

// Set holds the active whitelist policy for each provider.
//
// Policies reach the set through the deployment door: Install / InstallAll load
// Hub-predefined whitelists from the TEE's deployment config. They are trusted
// because they were placed in the configuration by the operator and their hash
// is bound into the TEE's attestation measurement. A policy that reaches
// Authorize is structurally valid and currently in effect.
type Set struct {
	mu       sync.RWMutex
	policies map[string]Policy
}

// NewSet returns an empty policy set.
func NewSet() *Set {
	return &Set{policies: make(map[string]Policy)}
}

// Install installs a Hub-predefined whitelist policy. The policy arrives with
// the TEE's deployment config, and its integrity is anchored by the
// attestation measurement (the policy-set hash is bound into the enclave
// evidence).
func (s *Set) Install(policy Policy, now time.Time) error {
	if err := policy.ValidateAt(now); err != nil {
		return err
	}
	if policy.Provider == "" {
		return errors.New("policy has no provider")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.policies[policy.Provider]; ok && policy.IssuedAt < current.IssuedAt {
		return fmt.Errorf("%w: incoming %d, installed %d",
			ErrPolicyRollback, policy.IssuedAt, current.IssuedAt)
	}
	s.policies[policy.Provider] = policy
	return nil
}

// InstallAll installs a batch of Hub-predefined whitelist policies, atomically.
// The TEE loads its entire policy configuration at startup from the deployment
// config, and the set must be all-or-nothing so a partial install cannot leave
// some providers silently unserviceable.
func (s *Set) InstallAll(policies []Policy, now time.Time) error {
	staged := make(map[string]Policy, len(policies))
	for _, p := range policies {
		if err := p.ValidateAt(now); err != nil {
			return err
		}
		if p.Provider == "" {
			return errors.New("policy has no provider")
		}
		staged[p.Provider] = p
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for provider, candidate := range staged {
		if current, ok := s.policies[provider]; ok && candidate.IssuedAt < current.IssuedAt {
			return fmt.Errorf("%w: %q incoming %d, installed %d",
				ErrPolicyRollback, provider, candidate.IssuedAt, current.IssuedAt)
		}
	}
	for provider, candidate := range staged {
		s.policies[provider] = candidate
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

	policy, ok := s.policies[provider]
	return policy, ok
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
	policy, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return policy.Authorize(spec)
}

// AuthorizeAt is Authorize plus both validity windows.
func (s *Set) AuthorizeAt(spec jobs.Spec, now time.Time) (Decision, error) {
	s.mu.RLock()
	policy, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return policy.AuthorizeAt(spec, now)
}

// Hash returns one deterministic digest for the whole policy set: the
// per-provider policy hashes, sorted by provider name, folded together with a
// domain separator. This is the value the TEE binds into its attestation
// measurement — changing any whitelist entry, adding a provider, or removing
// one all change the set hash, so a verifier can tell exactly which policy
// configuration an enclave was deployed with.
//
// An empty set is not an error (an operator may deploy with no policies, which
// means no provider can serve); it hashes to a fixed digest of nothing.
func (s *Set) Hash() ([32]byte, error) {
	s.mu.RLock()
	providers := make([]string, 0, len(s.policies))
	byProvider := make(map[string]Policy, len(s.policies))
	for provider, policy := range s.policies {
		providers = append(providers, provider)
		byProvider[provider] = policy
	}
	s.mu.RUnlock()
	sort.Strings(providers)

	h := sha256.New()
	h.Write([]byte(PolicySetHashDomain))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(providers)))
	h.Write(count[:])
	for _, provider := range providers {
		hash, err := byProvider[provider].Hash()
		if err != nil {
			return [32]byte{}, fmt.Errorf("hash policy for %q: %w", provider, err)
		}
		h.Write(hash[:])
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
