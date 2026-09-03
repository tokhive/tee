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
// precisely what an attacker would replay once a provider has tightened it.
var ErrPolicyRollback = errors.New("policy update is older than the installed policy")

// entry is one installed policy. Signature may be nil: TokenHive policies are
// Hub-predefined whitelists loaded from TEE deployment config (see Install),
// and the signed form is the legacy/compatibility path (see Add).
type entry struct {
	policy Policy
}

// Set holds the active policy for each provider.
//
// Policies reach the set through one of two doors:
//
//   - Install / InstallAll (the deployment door): a policy is loaded from the
//     TEE's deployment config as-is. It is trusted because it was placed in
//     the configuration by the operator and its hash is bound into the TEE's
//     attestation measurement — not because of a per-provider signature.
//   - Add (the compatibility door): a provider-signed policy is verified
//     before it is installed. This is the legacy path, kept so that providers
//     who want an extra layer of authorship can still sign.
//
// Either way a policy that reaches Authorize is structurally valid and
// currently in effect.
type Set struct {
	mu       sync.RWMutex
	policies map[string]entry
}

// NewSet returns an empty policy set.
func NewSet() *Set {
	return &Set{policies: make(map[string]entry)}
}

// Add verifies a signed policy and installs it for its provider. It is the
// compatibility door: the signed form predates Hub-predefined whitelists, and
// deployments that still carry provider signatures can keep using it. Most
// callers should use Install instead.
func (s *Set) Add(signed SignedPolicy, now time.Time) error {
	if err := VerifySignedPolicy(signed, now); err != nil {
		return err
	}
	return s.install(signed.Policy, now)
}

// Install installs a Hub-predefined whitelist policy without a provider
// signature. This is the deployment path: the policy arrives with the TEE's
// deployment config, and its integrity is anchored by the attestation
// measurement (the policy-set hash is bound into the enclave evidence), not by
// a per-provider key.
func (s *Set) Install(policy Policy, now time.Time) error {
	if err := policy.ValidateAt(now); err != nil {
		return err
	}
	return s.install(policy, now)
}

// install does the structural and rollback checks and stores the policy.
func (s *Set) install(policy Policy, now time.Time) error {
	if err := policy.ValidateAt(now); err != nil {
		return err
	}
	provider := policy.Provider
	if provider == "" {
		return errors.New("policy has no provider")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.policies[provider]; ok && policy.IssuedAt < current.policy.IssuedAt {
		return fmt.Errorf("%w: incoming %d, installed %d",
			ErrPolicyRollback, policy.IssuedAt, current.policy.IssuedAt)
	}
	s.policies[provider] = entry{policy: policy}
	return nil
}

// Load verifies and installs a batch of signed policies. It installs all of
// them or none: a partial policy set would leave some providers silently
// unserviceable, and a half-applied update is harder to reason about than a
// failed one. Prefer InstallAll for deployment config.
func (s *Set) Load(signed []SignedPolicy, now time.Time) error {
	staged := make(map[string]entry, len(signed))
	for _, signedEntry := range signed {
		if err := VerifySignedPolicy(signedEntry, now); err != nil {
			return err
		}
		staged[signedEntry.Policy.Provider] = entryFromPolicy(signedEntry.Policy)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for provider, candidate := range staged {
		if current, ok := s.policies[provider]; ok && candidate.policy.IssuedAt < current.policy.IssuedAt {
			return fmt.Errorf("%w: %q incoming %d, installed %d",
				ErrPolicyRollback, provider, candidate.policy.IssuedAt, current.policy.IssuedAt)
		}
	}
	for provider, candidate := range staged {
		s.policies[provider] = candidate
	}
	return nil
}

// InstallAll installs a batch of Hub-predefined whitelist policies without
// signatures, atomically. It is the deployment-path counterpart of Load: the
// TEE loads its entire policy configuration at startup from the deployment
// config, and the set must be all-or-nothing so a partial install cannot
// leave some providers silently unserviceable.
func (s *Set) InstallAll(policies []Policy, now time.Time) error {
	staged := make(map[string]entry, len(policies))
	for _, p := range policies {
		if err := p.ValidateAt(now); err != nil {
			return err
		}
		staged[p.Provider] = entryFromPolicy(p)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for provider, candidate := range staged {
		if current, ok := s.policies[provider]; ok && candidate.policy.IssuedAt < current.policy.IssuedAt {
			return fmt.Errorf("%w: %q incoming %d, installed %d",
				ErrPolicyRollback, provider, candidate.policy.IssuedAt, current.policy.IssuedAt)
		}
	}
	for provider, candidate := range staged {
		s.policies[provider] = candidate
	}
	return nil
}

func entryFromPolicy(p Policy) entry { return entry{policy: p} }

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

	e, ok := s.policies[provider]
	if !ok {
		return Policy{}, false
	}
	return e.policy, true
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
	e, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return e.policy.Authorize(spec)
}

// AuthorizeAt is Authorize plus both validity windows.
func (s *Set) AuthorizeAt(spec jobs.Spec, now time.Time) (Decision, error) {
	s.mu.RLock()
	e, ok := s.policies[spec.Provider]
	s.mu.RUnlock()

	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	return e.policy.AuthorizeAt(spec, now)
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
	for provider, e := range s.policies {
		providers = append(providers, provider)
		byProvider[provider] = e.policy
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
