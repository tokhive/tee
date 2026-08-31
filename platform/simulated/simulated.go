// Package simulated provides a software-only implementation of the
// platform.Epoch and platform.Adapter interfaces used by TokenHive.
//
// It exists for local development and the simulation harness. It does NOT
// provide real confidentiality or attestation: the "enclave" is an in-process
// ECDSA key and the "measurement" is a fixed, self-described blob. The point
// is that every caller above this layer — proof.Signer, proof.Verify, the Hub
// ledger — runs the exact same code path it would against a real SEV-SNP
// enclave. Only the trust root differs.
//
// That is deliberate: the plan forbids a simulation that silently diverges
// from production. A sim epoch must emit the same Identity shape (Platform,
// AttestationType, ApplicationID, Evidence, EvidenceHash, PublicKeyDER,
// KeyID) and sign with the same algorithm (ecdsa-p256-sha256-asn1) so that
// proof.Verify accepts its receipts unchanged.
package simulated

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

const (
	// Platform is the platform string carried in simulated attestations. The
	// verifier admits it via AllowedPlatforms=["simulated"].
	Platform = "simulated"

	// AttestationType labels the (fake) attestation format.
	AttestationType = "sim-software"

	// ApplicationID namespaces the simulated enclave image.
	ApplicationID = "tokenhive-sim@v1"

	// simMeasurement is a stand-in for the SEV-SNP "measurement" field: a
	// hash binding the enclave image. In a real enclave this is produced by
	// the hardware; here it is a fixed constant so the verifier can assert a
	// known-good value.
	simMeasurement = "000000000000000000000000000000000000000000000000000000000000dead"
)

// SimEvidence mirrors the subset of an SEV-SNP report a verifier cares about.
// Field names are chosen to line up with the real report so a future
// port from sim to sev-snp is a drop-in: same keys, different source.
type SimEvidence struct {
	// Version of the (simulated) attestation format.
	Version int `json:"version"`
	// Measurement binds the enclave image; the verifier checks it equals the
	// expected production measurement.
	Measurement string `json:"measurement"`
	// HostData is operator-supplied, enclave-bound data.
	HostData string `json:"host_data"`
	// Debug reports whether the enclave runs in debug mode. Production enclaves
	// must be false; a sim that flips this true simulates a compromised image.
	Debug bool `json:"debug"`
	// Policy is the SEV-SNP policy flags, here represented as a string for
	// readability.
	Policy string `json:"policy"`
}

// epoch is the software implementation of platform.Epoch.
type epoch struct {
	priv       *ecdsa.PrivateKey
	pubDER     []byte
	keyID      [32]byte
	evidence   []byte
	evidenceID SimEvidence
}

// NewEpoch generates a fresh software signing key and returns an epoch backed
// by it. Each call produces a different key, so the simulation can rotate
// epochs the way a real enclave would.
func NewEpoch() (platform.Epoch, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate sim key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal sim public key: %w", err)
	}
	keyID := sha256.Sum256(pubDER)

	ev := SimEvidence{
		Version:     1,
		Measurement: simMeasurement,
		HostData:    "tokenhive-simulation",
		Debug:       false,
		Policy:      "NO_DEBUG,NO_MIGRATE",
	}
	evidence, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal sim evidence: %w", err)
	}

	return &epoch{
		priv:       priv,
		pubDER:     pubDER,
		keyID:      keyID,
		evidence:   evidence,
		evidenceID: ev,
	}, nil
}

// Identity returns the public identity of this epoch, including the simulated
// attestation evidence and its hash.
func (e *epoch) Identity() platform.Identity {
	evHash := sha256Sum(e.evidence)

	return platform.Identity{
		Platform:        Platform,
		AttestationType: AttestationType,
		ApplicationID:   ApplicationID,
		Evidence:        append([]byte(nil), e.evidence...),
		EvidenceHash:    evHash,
		PublicKeyDER:    append([]byte(nil), e.pubDER...),
		KeyID:           e.keyID,
	}
}

// Sign produces a domain-separated ECDSA-P256-SHA256-ASN1 signature, identical
// in shape to what a real attested key would produce.
func (e *epoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, e.priv, digest[:])
	if err != nil {
		return platform.Signature{}, fmt.Errorf("sim sign: %w", err)
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.keyID,
		Value:     value,
	}, nil
}

// CheckEvidence verifies a simulated attestation the way a verifier would: the
// evidence parses, is not in debug mode, and carries the expected measurement.
// For a real enclave this step would validate the hardware signature chain
// against the operator's trust root instead.
func CheckEvidence(id platform.Identity) error {
	if id.Platform != Platform {
		return fmt.Errorf("unexpected platform %q", id.Platform)
	}
	if len(id.Evidence) == 0 {
		return errors.New("sim attestation has no evidence")
	}
	if sha256Sum(id.Evidence) != id.EvidenceHash {
		return errors.New("sim evidence hash mismatch")
	}
	var ev SimEvidence
	if err := json.Unmarshal(id.Evidence, &ev); err != nil {
		return fmt.Errorf("parse sim evidence: %w", err)
	}
	if ev.Debug {
		return errors.New("sim enclave is in DEBUG mode — untrusted")
	}
	if ev.Measurement != simMeasurement {
		return fmt.Errorf("sim measurement %q is not the trusted image", ev.Measurement)
	}
	return nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
