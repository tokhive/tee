package simulated

import (
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Verifier implements platform.EvidenceVerifier for the software attestation
// ecosystem. It delegates to the package-level CheckEvidence functions so the
// trust logic lives in exactly one place; the receiver exists only to satisfy
// the platform interface and to carry the platform string.
type Verifier struct{}

// Platform reports the software attestation platform string.
func (Verifier) Platform() string { return Platform }

// CheckEvidence validates inline simulated attestation evidence.
func (Verifier) CheckEvidence(id platform.Identity) error { return CheckEvidence(id) }

// CheckEvidenceForDeployment validates the evidence and asserts the deployment
// policy-set binding it carries.
func (Verifier) CheckEvidenceForDeployment(id platform.Identity, policySetHash [32]byte) error {
	return CheckEvidenceForDeployment(id, policySetHash)
}
