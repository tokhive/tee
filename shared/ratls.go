package shared

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// X.509 extension OID for the embedded GCP Confidential Space attestation JWT.
// Reclaim PEN = 65998; .1 reserved for the attestation extension.
var AttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65998, 1}

// AttestationOIDSEVSNP carries a marshaled go-sev-guest Attestation (raw
// SEV-SNP report + VCEK/ASK/ARK chain) for TEEs running on a plain SEV-SNP
// Confidential VM. Separate OID from .1 so verifiers dispatch on which
// extension is present and deployed Confidential Space certs (.1 only) keep
// verifying unchanged.
var AttestationOIDSEVSNP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65998, 2}

// AttestationOIDSecureBoot marks the legacy-compatible SNP envelope as Secure
// Boot evidence. The large evidence stays only in .2. Updated verifiers use
// this marker to retag that evidence and verify the release key R. Old clients
// ignore this non-critical extension and verify the unchanged SEV2 prerequisite.
var AttestationOIDSecureBoot = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65998, 3}

const secureBootRATLSExtensionVersion byte = 1

// SPKINoncePrefix returns the eat_nonce prefix used to bind the TLS public
// key hash into the attestation report. role is "tee_k" or "tee_t".
func SPKINoncePrefix(role string) string {
	return role + "_spki_hash:"
}

// SPKIHashFromCertDER parses the given DER-encoded X.509 certificate and
// returns sha256(MarshalPKIXPublicKey(cert.PublicKey)) — the value the
// SPKI nonce in an RA-TLS attestation binds to. This MUST be computed
// identically on all peers, so the implementation lives in one place.
//
// Used by:
//   - The TEEs when building the SPKI nonce for their per-session
//     attestation (binding the signed bundle to the TLS keypair, which
//     is invariant across cert refreshes).
//   - The TEEs when verifying the peer's per-session attestation against
//     the peer's TLS cert.
//   - The client when verifying TEE_K/TEE_T's per-session attestation
//     against the cert it saw on its WS connection.
func SPKIHashFromCertDER(certDER []byte) ([32]byte, error) {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse cert: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal SPKI: %w", err)
	}
	return sha256.Sum256(spkiDER), nil
}
