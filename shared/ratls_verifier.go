package shared

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// RATLSVerifyOptions controls the peer-certificate check installed via
// tls.Config.VerifyPeerCertificate. PeerRole is the role of the side whose
// cert we are about to verify ("tee_k" or "tee_t"); ExpectedImageDigest is
// the image digest we require the peer to attest to (matches the value
// passed via metadata at deploy time, e.g. EXPECTED_PEER_IMAGE_DIGEST).
type RATLSVerifyOptions struct {
	PeerRole            string
	ExpectedImageDigest string
	// ExpectedBaseDigest, when non-empty, pins the peer's per-cloud base UKI
	// (snp-base:<PCR11>). It may list both pair clouds' bases comma-separated, so
	// neither side needs to know which cloud its peer runs on; the peer's base
	// must match one. Empty (e.g. CS peers) skips the base check.
	ExpectedBaseDigest string
	Logger             *Logger
}

// validateRATLSCertStructure parses + validates an RA-TLS leaf cert
// without pinning a specific image_digest. Steps:
//
//  1. Pull the GCP attestation JWT out of the AttestationOID extension.
//  2. Validate JWT signature against Google's roots.
//  3. Confirm the SPKI hash nonce inside the JWT matches the cert's
//     actual SPKI (binds the keypair to this attestation).
//
// Returns the image_digest claim so callers can either pin it
// (TEE-to-TEE) or capture it for downstream use (clients).
//
// Standalone certs (no attestation extension) are rejected. Local-dev
// flows must avoid this verifier.
func validateRATLSCertStructure(rawCerts [][]byte, peerRole string, logger *Logger) (app, base string, err error) {
	if len(rawCerts) == 0 {
		return "", "", errors.New("ratls: no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", "", fmt.Errorf("ratls: parse peer cert: %w", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("ratls: marshal peer SPKI: %w", err)
	}
	actualHash := spkiSha256(spkiDER)

	_, snp, err := snpAttestationFromCert(leaf)
	if err != nil {
		return "", "", err
	}
	if snp != nil {
		return validateSEVSNP(snp, spkiDER)
	}
	if jwt := findExtension(leaf, AttestationOID); jwt != nil {
		app, err = validateGCPCS(jwt, peerRole, actualHash, logger)
		return app, "", err // CS has no separate base
	}
	return "", "", errors.New("ratls: attestation extension not present on certificate")
}

// snpAttestationFromCert returns the effective SNP generation and evidence.
// Secure Boot certificates keep their evidence under the legacy .2 OID and add
// a small .3 marker. Native-tag .2 certificates from the initial deployment
// remain accepted during migration.
func snpAttestationFromCert(cert *x509.Certificate) (string, []byte, error) {
	legacy := findExtension(cert, AttestationOIDSEVSNP)
	if marker := findExtension(cert, AttestationOIDSecureBoot); marker != nil {
		if len(marker) != 1 || marker[0] != secureBootRATLSExtensionVersion {
			return "", nil, errors.New("ratls: unsupported Secure Boot extension version")
		}
		if legacy == nil {
			return "", nil, errors.New("ratls: Secure Boot marker has no SNP evidence")
		}
		secure, err := SecureBootAttestationFromCompatibleWire(legacy)
		if err != nil {
			return "", nil, fmt.Errorf("ratls: Secure Boot evidence: %w", err)
		}
		return AttestationTypeSecureBoot, secure, nil
	}
	if legacy == nil {
		return "", nil, nil
	}
	if IsSecureBootAttestation(legacy) {
		return AttestationTypeSecureBoot, legacy, nil
	}
	return AttestationTypeSEVSNP, legacy, nil
}

// validateGCPCS verifies a Confidential Space attestation JWT, binds the SPKI
// nonce to the cert's actual key, and returns the container image_digest.
func validateGCPCS(attestation []byte, peerRole string, actualHash [32]byte, logger *Logger) (string, error) {
	attestor, err := NewGoogleAttestor()
	if err != nil {
		return "", fmt.Errorf("ratls: build attestor: %w", err)
	}
	if err := attestor.Validate(attestation, logger); err != nil {
		return "", fmt.Errorf("ratls: attestation invalid: %w", err)
	}

	imageDigest, err := ExtractImageDigestFromGCPAttestation(attestation, logger)
	if err != nil {
		return "", fmt.Errorf("ratls: extract image digest: %w", err)
	}

	actualHex := hex.EncodeToString(actualHash[:])
	expectedHex, err := FindNonceValue(attestation, SPKINoncePrefix(peerRole))
	if err != nil {
		return "", fmt.Errorf("ratls: %w", err)
	}
	if expectedHex != actualHex {
		return "", fmt.Errorf("ratls: SPKI hash mismatch: attestation says %q, cert is %q",
			expectedHex, actualHex)
	}
	return imageDigest, nil
}

// validateSEVSNP verifies a combined vTPM+SEV-SNP attestation: the AK cert chains
// to the Google vTPM root, the SEV report to the AMD root, report_data binds the
// AK to this cert's SPKI (anti-splice), and the AK-signed quote pins PCR 8 (app)
// + PCR 11 (base). Returns the app (payload) identity "snp-app:<hex(appHash)>".
func validateSEVSNP(attestation, spkiDER []byte) (string, string, error) {
	if IsSecureBootAttestation(attestation) {
		app, _, err := VerifyCombinedSecureBootAttestation(attestation, spkiDER)
		if err != nil {
			return "", "", fmt.Errorf("ratls: %w", err)
		}
		// Secure Boot replaces the per-base PCR 11 pin with the embedded R key.
		return app, "", nil
	}
	app, base, err := VerifyCombinedSEVSNPAttestation(attestation, spkiDER)
	if err != nil {
		return "", "", fmt.Errorf("ratls: %w", err)
	}
	return app, base, nil
}

// findExtension returns the value of the first cert extension matching oid, or
// nil if absent.
func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value
		}
	}
	return nil
}

// VerifyRATLSPeer returns a tls.Config.VerifyPeerCertificate callback for
// TEE↔TEE mTLS: validates the cert structure and pins the image_digest
// to opts.ExpectedImageDigest. Any failure aborts the TLS handshake.
func VerifyRATLSPeer(opts RATLSVerifyOptions) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		gotDigest, gotBase, err := validateRATLSCertStructure(rawCerts, opts.PeerRole, opts.Logger)
		if err != nil {
			return err
		}
		if gotDigest != opts.ExpectedImageDigest {
			return fmt.Errorf("ratls: image_digest mismatch: expected %q, got %q",
				opts.ExpectedImageDigest, gotDigest)
		}
		// Pin the per-cloud base UKI when configured (SEV-SNP pairs). An honest
		// TEE refuses to MPC with a peer whose base isn't an expected one.
		if opts.ExpectedBaseDigest != "" && !baseAccepted(opts.ExpectedBaseDigest, gotBase) {
			return fmt.Errorf("ratls: peer base %q not in expected set %q", gotBase, opts.ExpectedBaseDigest)
		}
		return nil
	}
}

// baseAccepted reports whether gotBase is one of the comma-separated expected
// base UKIs. Listing both pair clouds' bases lets either side accept its peer
// without knowing which cloud the peer runs on.
func baseAccepted(expected, gotBase string) bool {
	for b := range strings.SplitSeq(expected, ",") {
		if strings.TrimSpace(b) == gotBase {
			return true
		}
	}
	return false
}

// VerifyRATLSAttestation returns a tls.Config.VerifyPeerCertificate
// callback for CLIENT→TEE connections: validates cert structure +
// attestation integrity without pinning image_digest.
//
// Clients deliberately do NOT pin image_digest themselves — the TEEs
// embed their full attestation reports into the signed claim bundles
// the attestor later inspects. The client's only job at TLS time is to
// confirm the cert is genuine RA-TLS (Google-signed attestation + SPKI
// binding). What's INSIDE the attestation is decided downstream.
func VerifyRATLSAttestation(peerRole string, logger *Logger) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		_, _, err := validateRATLSCertStructure(rawCerts, peerRole, logger)
		return err
	}
}

// ExtractAttestationFromCert returns the raw GCP attestation JWT bytes from
// the AttestationOID X.509 extension on the given cert, or an error if the
// extension is missing.
func ExtractAttestationFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AttestationOID) {
			return ext.Value, nil
		}
	}
	return nil, errors.New("attestation extension not present on certificate")
}

// FindNonceInList returns the substring after the first nonce that starts with
// prefix. It is the SEV-SNP analogue of FindNonceValue: the nonces come from a
// VerifyCombinedSEVSNPNonceAttestation result (already hardware-attested), so no
// JWT parsing is involved.
func FindNonceInList(nonces []string, prefix string) (string, error) {
	for _, n := range nonces {
		if val, ok := strings.CutPrefix(n, prefix); ok {
			return val, nil
		}
	}
	return "", fmt.Errorf("nonce with prefix %q not found", prefix)
}

// FindNonceValue inspects the eat_nonce claim of an attestation JWT for a
// nonce starting with the given prefix and returns the substring after the
// prefix. Handles both string and []any forms of eat_nonce.
//
// Does NOT validate the JWT signature — call attestor.Validate first. The
// attestation parameter is the raw JWT bytes.
func FindNonceValue(attestation []byte, prefix string) (string, error) {
	tokenStr := strings.TrimSpace(string(attestation))
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	raw, ok := claims["eat_nonce"]
	if !ok {
		return "", errors.New("eat_nonce missing from attestation")
	}
	switch v := raw.(type) {
	case string:
		if val, ok := strings.CutPrefix(v, prefix); ok {
			return val, nil
		}
	case []any:
		for _, n := range v {
			s, ok := n.(string)
			if !ok {
				continue
			}
			if val, ok := strings.CutPrefix(s, prefix); ok {
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("nonce with prefix %q not found", prefix)
}
