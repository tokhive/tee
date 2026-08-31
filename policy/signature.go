package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// ErrInvalidProviderKey is returned when a signing key is not a P-256 ECDSA
// key. The policy is signed by the credential owner, not by a user.
var ErrInvalidProviderKey = errors.New("provider key must be an ECDSA P-256 key")

// SignedPolicy is a policy together with the credential owner's signature.
type SignedPolicy struct {
	Policy    Policy             `cbor:"1,keyasint"`
	Signature platform.Signature `cbor:"2,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of a signed policy.
func (s SignedPolicy) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(s)
}

// Hash returns the hash of the enclosed policy, which is stable regardless of
// the signature and is the value external systems should cite.
func (s SignedPolicy) Hash() ([32]byte, error) {
	return s.Policy.Hash()
}

// SignPolicy signs a policy with the credential owner's key.
//
// The policy's ProviderKey is overwritten with the signing key's public half.
// Letting a caller supply both independently would allow a policy naming one
// owner to carry a signature from another, which is exactly the confusion this
// signature exists to prevent.
//
// SignPolicy validates the policy's structure but not its validity window:
// a provider is allowed to pre-sign a policy that takes effect later.
func SignPolicy(policy Policy, key *ecdsa.PrivateKey) (SignedPolicy, error) {
	var empty SignedPolicy

	if key == nil {
		return empty, fmt.Errorf("%w: nil key", ErrInvalidProviderKey)
	}
	if key.Curve != elliptic.P256() {
		return empty, fmt.Errorf("%w: curve %q", ErrInvalidProviderKey, key.Curve.Params().Name)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return empty, fmt.Errorf("encode provider public key: %w", err)
	}
	policy.ProviderKey = publicKeyDER

	if err := policy.Validate(); err != nil {
		return empty, err
	}

	policyHash, err := policy.Hash()
	if err != nil {
		return empty, err
	}
	digest, err := platform.SigningDigest(PolicySigningDomain, policyHash[:])
	if err != nil {
		return empty, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return empty, fmt.Errorf("sign policy: %w", err)
	}

	return SignedPolicy{
		Policy: policy,
		Signature: platform.Signature{
			Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
			KeyID:     sha256.Sum256(publicKeyDER),
			Value:     value,
		},
	}, nil
}

// VerifySignedPolicy checks that a signed policy is well-formed, currently in
// effect, and signed by the key it names.
//
// Passing a zero time skips the validity window check, which is only
// appropriate when verifying a historical policy against its own epoch rather
// than against now.
func VerifySignedPolicy(signed SignedPolicy, now time.Time) error {
	if err := signed.Policy.Validate(); err != nil {
		return err
	}
	if !now.IsZero() {
		if err := signed.Policy.ValidateAt(now); err != nil {
			return err
		}
	}

	policyHash, err := signed.Policy.Hash()
	if err != nil {
		return err
	}

	// The signing key is the one the policy itself names, so a policy is
	// self-certifying: no external registry is needed to find the right public
	// key, and no registry mismatch is possible.
	identity := platform.Identity{
		PublicKeyDER: signed.Policy.ProviderKey,
		KeyID:        sha256.Sum256(signed.Policy.ProviderKey),
	}
	return platform.VerifySignature(identity, PolicySigningDomain, policyHash[:], signed.Signature)
}

// DecodeSignedPolicy decodes a canonical-CBOR signed policy. Decoding enforces
// canonical form, so a policy rewritten into an equivalent but non-canonical
// encoding is rejected instead of being accepted under a different hash.
func DecodeSignedPolicy(data []byte) (SignedPolicy, error) {
	var signed SignedPolicy
	if err := canonical.Unmarshal(data, &signed); err != nil {
		return SignedPolicy{}, err
	}
	return signed, nil
}
