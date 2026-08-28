// Package platform defines the trusted-runtime interface used by TokenHive.
// Platform-specific attestation details stay behind Adapter.
package platform

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// PlatformAWSSEVSNP identifies an AWS confidential VM backed by AMD SEV-SNP.
	PlatformAWSSEVSNP = "aws-sev-snp"

	// SignatureAlgorithmECDSAP256SHA256ASN1 is the RA-TLS epoch key algorithm.
	SignatureAlgorithmECDSAP256SHA256ASN1 = "ecdsa-p256-sha256-asn1"

	maxSigningDomainLength = 65535
)

var (
	// ErrNotReady means the platform cannot currently admit trusted work.
	ErrNotReady = errors.New("TEE platform is not ready")
	// ErrInvalidSigningDomain means a caller did not provide a usable domain.
	ErrInvalidSigningDomain = errors.New("invalid signing domain")
)

// Identity is the public identity of one attested key epoch.
type Identity struct {
	Platform        string
	AttestationType string
	ApplicationID   string
	Evidence        []byte
	EvidenceHash    [32]byte
	PublicKeyDER    []byte
	KeyID           [32]byte
}

// Signature is a domain-separated signature made by an attested epoch key.
type Signature struct {
	Algorithm string
	KeyID     [32]byte
	Value     []byte
}

// Epoch keeps evidence, public identity, and signing capability on the same
// immutable RA-TLS key epoch.
type Epoch interface {
	Identity() Identity
	Sign(domain string, payload []byte) (Signature, error)
}

// Adapter exposes the small platform surface needed by the TokenHive runtime.
type Adapter interface {
	ServerTLSConfig() *tls.Config
	Snapshot(context.Context) (Epoch, error)
	Refresh(context.Context) error
	Healthy() bool
}

// SigningDigest constructs an unambiguous, domain-separated SHA-256 digest.
func SigningDigest(domain string, payload []byte) ([32]byte, error) {
	if len(domain) == 0 || len(domain) > maxSigningDomainLength {
		return [32]byte{}, fmt.Errorf("%w: length %d", ErrInvalidSigningDomain, len(domain))
	}

	h := sha256.New()
	h.Write([]byte("TokenHive.AttestedSignature.v1"))
	var domainLength [2]byte
	binary.BigEndian.PutUint16(domainLength[:], uint16(len(domain)))
	h.Write(domainLength[:])
	h.Write([]byte(domain))
	var payloadLength [8]byte
	binary.BigEndian.PutUint64(payloadLength[:], uint64(len(payload)))
	h.Write(payloadLength[:])
	h.Write(payload)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// VerifySignature verifies a signature against identity's public key for the
// exact domain and payload. Callers must validate the platform attestation in
// Identity before treating the key as trusted.
func VerifySignature(identity Identity, domain string, payload []byte, signature Signature) error {
	if signature.Algorithm != SignatureAlgorithmECDSAP256SHA256ASN1 {
		return fmt.Errorf("unsupported signature algorithm %q", signature.Algorithm)
	}
	computedKeyID := sha256.Sum256(identity.PublicKeyDER)
	if !bytes.Equal(computedKeyID[:], identity.KeyID[:]) {
		return errors.New("identity key ID does not match public key")
	}
	if !bytes.Equal(signature.KeyID[:], identity.KeyID[:]) {
		return errors.New("signature key ID does not match identity")
	}

	parsed, err := x509.ParsePKIXPublicKey(identity.PublicKeyDER)
	if err != nil {
		return fmt.Errorf("parse attested public key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("attested public key has type %T, want ECDSA", parsed)
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("attested public key uses curve %q, want P-256", publicKey.Curve.Params().Name)
	}
	digest, err := SigningDigest(domain, payload)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature.Value) {
		return errors.New("invalid attested signature")
	}
	return nil
}

// CloneIdentity prevents callers from mutating an epoch's cached identity.
func CloneIdentity(identity Identity) Identity {
	identity.Evidence = append([]byte(nil), identity.Evidence...)
	identity.PublicKeyDER = append([]byte(nil), identity.PublicKeyDER...)
	return identity
}
