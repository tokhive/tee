// Package attest is the Trusted-Compute verifier for TokenHive receipts. It
// turns proof.Verify's "an attested key produced this signature" into "the
// enclave image this deployment trusts produced it".
//
// proof.Verify checks structure, platform allow-list, and the signature against
// the attested key named in the receipt. It deliberately does not judge the
// attestation itself — that is the deployer's call, and it is this package's.
// A Verifier:
//
//  1. resolves the full attestation evidence for a receipt that carries only an
//     EvidenceHash (the small, cheap receipt form) by asking its Fetcher;
//  2. validates the evidence through the platform's EvidenceVerifier, asserting
//     the trusted measurement and, when the caller knows the deployment, the
//     policy-set configuration bound into it;
//  3. refuses anything outside the caller's AllowedPlatforms.
//
// All three are configurable so a Hub, an auditor, or a provider can each
// verify against their own trust root without changing the wire format.
package attest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Fetcher resolves a hash-only attestation reference to full evidence, keyed by
// the identity's platform, application ID and evidence hash. It is the
// "attestation cache" half of offline verification: receipts are small because
// they carry a hash, and the full report arrives from wherever the deployment
// saw the TEE come online.
//
// Implementations must return the evidence bytes whose SHA-256 equals
// id.EvidenceHash. A Fetcher that cannot produce them must return an error so
// the receipt is refused rather than silently trusted on a hash alone.
type Fetcher interface {
	Fetch(ctx context.Context, id platform.Identity) ([]byte, error)
}

// FuncFetcher adapts a bare function to the Fetcher interface.
type FuncFetcher func(ctx context.Context, id platform.Identity) ([]byte, error)

// Fetch calls the wrapped function.
func (f FuncFetcher) Fetch(ctx context.Context, id platform.Identity) ([]byte, error) {
	return f(ctx, id)
}

// defaultProofOptions mirrors the canonical receipt verification: no offline
// cache means evidence must be inline; MaxAge is deliberately off here because
// freshness is a policy choice the caller owns.
var errFetcherMiss = errors.New("attestation evidence not in cache")

// Cache is an in-memory Fetcher, populated when a trusted TEE is seen online.
// It is keyed by platform, application ID and evidence hash so that several
// concurrent TEEs (or the same app across restarts) never collide.
type Cache struct {
	mu sync.Mutex
	m  map[cacheKey][]byte
}

type cacheKey struct {
	platform string
	app      string
	evHash   [32]byte
}

// Put stores the full evidence of an identity, keyed for later hash-only
// resolution.
func (c *Cache) Put(id platform.Identity) {
	if len(id.Evidence) == 0 {
		return
	}
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[cacheKey][]byte)
	}
	c.m[cacheKey{platform: id.Platform, app: id.ApplicationID, evHash: id.EvidenceHash}] = append([]byte(nil), id.Evidence...)
}

// Fetch implements Fetcher.
func (c *Cache) Fetch(_ context.Context, id platform.Identity) ([]byte, error) {
	if c == nil {
		return nil, errFetcherMiss
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ev, ok := c.m[cacheKey{platform: id.Platform, app: id.ApplicationID, evHash: id.EvidenceHash}]
	if !ok {
		return nil, errFetcherMiss
	}
	if sum := sha256Sum(ev); sum != id.EvidenceHash {
		return nil, errFetcherMiss
	}
	return append([]byte(nil), ev...), nil
}

// Config assembles a Verifier. It is the deployer's trust-root statement.
type Config struct {
	// AllowedPlatforms is the trust root: only these attestation platforms are
	// acceptable, and a receipt from anything else is refused. Required — a
	// verifier that accepts everything trusts nothing.
	AllowedPlatforms []string

	// ByPlatform maps an attestation platform string to its evidence verifier.
	// A platform appearing in AllowedPlatforms but absent here fails closed.
	ByPlatform map[string]platform.EvidenceVerifier

	// Fetcher resolves evidence for receipts that carry only an EvidenceHash.
	// Nil means receipts must carry the full evidence inline. Whether the
	// deployment ships small hash-only receipts or self-contained ones is its
	// choice; the verifier accepts either when a Fetcher is set.
	Fetcher Fetcher

	// PolicySetHash, when non-zero, requires every receipt's evidence to carry
	// a deployment binding to exactly this whitelist digest. It is how an
	// auditor proves a receipt is not just from the trusted image, but from the
	// trusted image configured with the policy set the deployment shipped. Zero
	// skips the deployment-binding assertion.
	PolicySetHash [32]byte
}

// Verifier validates signed receipts end to end against a deployer-chosen trust
// root. It is safe for concurrent use.
type Verifier struct {
	allowed    map[string]struct{}
	byPlatform map[string]platform.EvidenceVerifier
	fetcher    Fetcher

	havePolicy    bool
	policySetHash [32]byte
}

// New validates a Config and returns a ready Verifier.
func New(cfg Config) (*Verifier, error) {
	if len(cfg.AllowedPlatforms) == 0 {
		return nil, errors.New("attest: AllowedPlatforms is empty")
	}
	mentioned := make(map[string]struct{}, len(cfg.AllowedPlatforms))
	allowed := make(map[string]struct{}, len(cfg.AllowedPlatforms))
	for _, p := range cfg.AllowedPlatforms {
		if p == "" {
			return nil, errors.New("attest: empty platform in AllowedPlatforms")
		}
		allowed[p] = struct{}{}
		mentioned[p] = struct{}{}
	}
	for p := range cfg.ByPlatform {
		if p == "" {
			return nil, errors.New("attest: empty platform key in ByPlatform")
		}
	}

	v := &Verifier{
		allowed:    allowed,
		byPlatform: cfg.ByPlatform,
		fetcher:    cfg.Fetcher,
		havePolicy: cfg.PolicySetHash != [32]byte{},
	}
	if cfg.PolicySetHash != [32]byte{} {
		v.policySetHash = cfg.PolicySetHash
	}

	// A platform the operator advertises as trusted but provides no verifier
	// for is a wiring mistake, not a runtime surprise.
	for p := range mentioned {
		if _, ok := cfg.ByPlatform[p]; !ok {
			return nil, fmt.Errorf("attest: platform %q allowed but has no evidence verifier", p)
		}
	}
	return v, nil
}

// Check validates a signed receipt's signature and, crucially, its attestation
// evidence's trust. It is the single entry point a Hub or auditor calls instead
// of proof.Verify.
func (v *Verifier) Check(signed proof.SignedReceipt) error {
	if v == nil {
		return errors.New("attest: nil verifier")
	}
	ref := signed.Receipt.Attestation
	if ref == nil {
		return proof.ErrMissingAttestation
	}
	if _, ok := v.allowed[ref.Platform]; !ok {
		return fmt.Errorf("%w: %q", proof.ErrPlatformNotAllowed, ref.Platform)
	}

	// Structure, policy constraints, and the signature against the attested key.
	// RequireEvidence only when we cannot resolve a hash-only receipt, so a
	// deployment with a Fetcher may ship the small receipt form.
	requireEvidence := v.fetcher == nil
	if err := proof.Verify(signed, proof.VerifyOptions{
		AllowedPlatforms: v.allowedList(),
		RequireEvidence:  requireEvidence,
	}); err != nil {
		return err
	}

	id, err := signed.Receipt.Identity()
	if err != nil {
		return err
	}

	// Resolve full evidence for a hash-only reference. The Fetcher must return
	// bytes whose hash matches; refusing on a miss is what makes the hash
	// meaningful rather than decorative.
	if len(id.Evidence) == 0 {
		ev, err := v.fetcher.Fetch(context.Background(), id)
		if err != nil {
			return fmt.Errorf("resolve attestation evidence: %w", err)
		}
		id.Evidence = ev
	}

	// The platform's evidence verifier is the last word: it checks the trust
	// chain and the measured image, and (optionally) the deployment binding.
	platformVerifier, ok := v.byPlatform[id.Platform]
	if !ok {
		return fmt.Errorf("attest: no evidence verifier for platform %q", id.Platform)
	}
	if v.havePolicy {
		return platformVerifier.CheckEvidenceForDeployment(id, v.policySetHash)
	}
	return platformVerifier.CheckEvidence(id)
}

// VerifyFunc adapts Check to the signature the Hub and the receipt store expect
// (func(proof.SignedReceipt) error), so a Verifier drops straight into
// hub.Config.Verify and store.Audit.
func (v *Verifier) VerifyFunc() func(proof.SignedReceipt) error {
	return func(signed proof.SignedReceipt) error { return v.Check(signed) }
}

// AllowedPlatforms returns the platforms this verifier trusts, sorted for
// determinism.
func (v *Verifier) AllowedPlatforms() []string {
	return v.allowedList()
}

func (v *Verifier) allowedList() []string {
	if v == nil {
		return nil
	}
	out := make([]string, 0, len(v.allowed))
	for p := range v.allowed {
		out = append(out, p)
	}
	sortStrings(out)
	return out
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// sortStrings sorts a string slice ascending in place.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
