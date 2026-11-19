package proof

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/tokhive/tee/internal/canonical"
	"github.com/tokhive/tee/platform"
)

const (
	// CredentialKeySigningDomain separates the credential-key statement from
	// receipts. Both are signed by the same attested epoch key, so the domain is
	// the only thing preventing one signature from being replayed as the other.
	CredentialKeySigningDomain = "TokenHive.CredentialKey.v1"

	// CredentialKeyNonceLength is the length of the verifier challenge. The
	// nonce is what stops an old, genuinely signed inbox key from being replayed
	// after the TEE that owns it has rebooted.
	CredentialKeyNonceLength = 32
)

// Credential-key statement validation errors.
var (
	ErrUnsupportedCredentialKeyVersion = errors.New("unsupported credential-key version")
	ErrInvalidCredentialKeyNonce       = errors.New("invalid credential-key nonce")
	ErrCredentialKeyNonceMismatch      = errors.New("credential-key nonce does not match")
	ErrInvalidInboxKey                 = errors.New("invalid inbox key")
	ErrInboxKeyMismatch                = errors.New("inbox key does not match the attested statement")
	ErrCredentialKeyPolicyMismatch     = errors.New("credential-key policy hash does not match")
	ErrCredentialKeyTooOld             = errors.New("credential-key statement is older than the allowed window")
)

// CredentialKeyStatement binds the TEE's long-lived credential inbox key to the
// attested epoch key that signs it.
//
// The epoch key is the same key that signs execution receipts and is bound to
// the measured image by the evidence. The inbox key lives only inside the same
// enclave and is the key providers encrypt credentials to. This statement is
// therefore the missing link between "this evidence names the image I trust" and
// "this X25519 key belongs to that image".
type CredentialKeyStatement struct {
	Version     uint32          `cbor:"1,keyasint"`
	Nonce       []byte          `cbor:"2,keyasint"`
	InboxKeyID  []byte          `cbor:"3,keyasint"`
	InboxPublic []byte          `cbor:"4,keyasint"`
	PolicyHash  []byte          `cbor:"5,keyasint"`
	IssuedAt    int64           `cbor:"6,keyasint"`
	Attestation *AttestationRef `cbor:"7,keyasint,omitempty"`
}

// SignedCredentialKey is the signature over a CredentialKeyStatement.
type SignedCredentialKey struct {
	Statement CredentialKeyStatement `cbor:"1,keyasint"`
	Signature platform.Signature     `cbor:"2,keyasint"`
}

// Validate checks the statement's structure and that the claimed inbox key ID
// hashes the claimed inbox public key. It deliberately does not verify the
// signature or the evidence; those need the verifier's trust roots.
func (s CredentialKeyStatement) Validate() error {
	if s.Version != VersionV1 {
		return fmt.Errorf("%w: %d", ErrUnsupportedCredentialKeyVersion, s.Version)
	}
	if len(s.Nonce) != CredentialKeyNonceLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidCredentialKeyNonce, len(s.Nonce), CredentialKeyNonceLength)
	}
	if len(s.InboxKeyID) != sha256.Size {
		return fmt.Errorf("%w: key ID length %d, want %d", ErrInvalidInboxKey, len(s.InboxKeyID), sha256.Size)
	}
	if len(s.PolicyHash) != PolicyHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidPolicyHash, len(s.PolicyHash), PolicyHashLength)
	}
	if s.IssuedAt <= 0 {
		return fmt.Errorf("%w: issued at %d", ErrInvalidInboxKey, s.IssuedAt)
	}
	if err := validateInboxPublic(s.InboxPublic); err != nil {
		return err
	}
	if computed := sha256.Sum256(s.InboxPublic); subtle.ConstantTimeCompare(computed[:], s.InboxKeyID) != 1 {
		return fmt.Errorf("%w: inbox key ID does not match the public key", ErrInvalidInboxKey)
	}
	return validateAttestation(s.Attestation)
}

// Identity reconstructs the signing identity from the attestation reference.
func (s CredentialKeyStatement) Identity() (platform.Identity, error) {
	return identityFromAttestation(s.Attestation)
}

// EncodeCanonical returns the deterministic CBOR encoding of a credential-key
// statement. This is the byte string the epoch key signs.
func (s CredentialKeyStatement) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(s)
}

// EncodeCanonical returns the deterministic CBOR encoding of a signed
// credential-key statement, suitable for transport or storage.
func (s SignedCredentialKey) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(s)
}

// DecodeCredentialKey decodes a canonical-CBOR signed credential-key statement.
// Decoding rejects any bytes that would not re-encode identically.
func DecodeCredentialKey(data []byte) (SignedCredentialKey, error) {
	var signed SignedCredentialKey
	if err := canonical.Unmarshal(data, &signed); err != nil {
		return SignedCredentialKey{}, err
	}
	return signed, nil
}

// SignCredentialKey validates and signs a statement, filling in the attestation
// reference from the signer's epoch. The full evidence is always embedded: a
// provider verifying this statement has no attestation cache and must be able to
// verify it offline.
func (s *Signer) SignCredentialKey(statement CredentialKeyStatement) (SignedCredentialKey, error) {
	var empty SignedCredentialKey

	if s == nil || s.epoch == nil {
		return empty, ErrNoEpoch
	}

	identity := s.epoch.Identity()
	statement.Attestation = &AttestationRef{
		Platform:        identity.Platform,
		AttestationType: identity.AttestationType,
		ApplicationID:   identity.ApplicationID,
		KeyID:           identity.KeyID[:],
		PublicKeyDER:    identity.PublicKeyDER,
		EvidenceHash:    identity.EvidenceHash[:],
		Evidence:        identity.Evidence,
	}
	if len(statement.Attestation.Evidence) == 0 {
		return empty, ErrEvidenceRequired
	}
	if err := statement.Validate(); err != nil {
		return empty, err
	}

	encoded, err := statement.EncodeCanonical()
	if err != nil {
		return empty, err
	}
	signature, err := s.epoch.Sign(CredentialKeySigningDomain, encoded)
	if err != nil {
		return empty, fmt.Errorf("sign credential key: %w", err)
	}
	return SignedCredentialKey{Statement: statement, Signature: signature}, nil
}

// CredentialKeyVerifyOptions constrains what a provider is willing to encrypt
// to. Nonce and PolicyHash are the two values a compromised relay cannot forge.
type CredentialKeyVerifyOptions struct {
	// Nonce is the challenge the provider generated for this fetch. Empty
	// disables the freshness check, which only makes sense for pinned fixtures.
	Nonce []byte
	// PolicyHash is the whitelist the provider expects the TEE to enforce.
	PolicyHash []byte
	// AllowedPlatforms restricts which attestation platforms are trusted. Empty
	// means no restriction beyond a well-formed platform string.
	AllowedPlatforms []string
	// RequireEvidence rejects statements without inline attestation evidence.
	RequireEvidence bool
	// Now is the verifier's clock. Zero means time.Now().
	Now time.Time
	// MaxAge rejects statements issued longer ago than this. Zero disables the
	// check; the nonce already bounds replay.
	MaxAge time.Duration
}

// VerifyCredentialKey checks the statement structure, the freshness nonce, the
// expected policy, and the signature against the attested key named in the
// statement.
//
// It does not resolve the evidence to a trusted measurement. That is the
// caller's responsibility and is what turns "an enclave signed this" into "the
// enclave I trust signed this".
func VerifyCredentialKey(signed SignedCredentialKey, opts CredentialKeyVerifyOptions) error {
	if err := signed.Statement.Validate(); err != nil {
		return err
	}
	if len(opts.Nonce) > 0 {
		if len(opts.Nonce) != CredentialKeyNonceLength {
			return fmt.Errorf("%w: verifier nonce length %d, want %d",
				ErrInvalidCredentialKeyNonce, len(opts.Nonce), CredentialKeyNonceLength)
		}
		if subtle.ConstantTimeCompare(signed.Statement.Nonce, opts.Nonce) != 1 {
			return ErrCredentialKeyNonceMismatch
		}
	}
	if len(opts.PolicyHash) > 0 {
		if len(opts.PolicyHash) != PolicyHashLength {
			return fmt.Errorf("%w: verifier policy hash length %d, want %d",
				ErrInvalidPolicyHash, len(opts.PolicyHash), PolicyHashLength)
		}
		if subtle.ConstantTimeCompare(signed.Statement.PolicyHash, opts.PolicyHash) != 1 {
			return ErrCredentialKeyPolicyMismatch
		}
	}
	if opts.RequireEvidence && len(signed.Statement.Attestation.Evidence) == 0 {
		return ErrEvidenceRequired
	}
	if len(opts.AllowedPlatforms) > 0 && !containsString(opts.AllowedPlatforms, signed.Statement.Attestation.Platform) {
		return fmt.Errorf("%w: %q", ErrPlatformNotAllowed, signed.Statement.Attestation.Platform)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if opts.MaxAge > 0 {
		issued := time.Unix(signed.Statement.IssuedAt, 0)
		if now.Sub(issued) > opts.MaxAge {
			return fmt.Errorf("%w: issued %v, now %v", ErrCredentialKeyTooOld, issued, now)
		}
	}

	identity, err := signed.Statement.Identity()
	if err != nil {
		return err
	}
	// The signature must have been made by the key the statement names.
	if subtle.ConstantTimeCompare(signed.Signature.KeyID[:], identity.KeyID[:]) != 1 {
		return fmt.Errorf("%w: signature key ID %x, statement key ID %x",
			ErrAttestationMismatch, signed.Signature.KeyID, identity.KeyID)
	}

	encoded, err := signed.Statement.EncodeCanonical()
	if err != nil {
		return err
	}
	return platform.VerifySignature(identity, CredentialKeySigningDomain, encoded, signed.Signature)
}

// DecodeAndVerifyCredentialKey decodes a canonical-CBOR signed statement and
// verifies it. Decoding enforces canonical form before any signature is trusted.
func DecodeAndVerifyCredentialKey(data []byte, opts CredentialKeyVerifyOptions) (SignedCredentialKey, error) {
	signed, err := DecodeCredentialKey(data)
	if err != nil {
		return SignedCredentialKey{}, err
	}
	if err := VerifyCredentialKey(signed, opts); err != nil {
		return SignedCredentialKey{}, err
	}
	return signed, nil
}

func validateInboxPublic(der []byte) error {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInboxKey, err)
	}
	key, ok := parsed.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return fmt.Errorf("%w: not an X25519 public key", ErrInvalidInboxKey)
	}
	return nil
}
