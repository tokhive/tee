package alicloud

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Verifier implements platform.EvidenceVerifier for Alibaba Cloud confidential
// computing.
//
// STATUS: SKELETON. This deliberately refuses every alicloud receipt with
// platform.ErrAttestationNotImplemented. Implementing CheckEvidence requires
// validating Alibaba's remote-attestation protocol — for an SGX instance the
// ECDSA quote chain against Alibaba's attestation service (or Intel PCCS), for
// a TDX guest the TDX quote, for an SEV-SNP guest the AMD report via the same
// offline go-sev-guest path the AWS adapter uses — and pinning the trusted
// measured image. Until that lands, no alicloud receipt may verify, which is
// exactly what this code enforces.
type Verifier struct{}

// Platform reports the Alibaba Cloud platform string.
func (v Verifier) Platform() string { return platform.PlatformAlibabaCloud }

// CheckEvidence refuses the attestation: the alicloud evidence path is not
// implemented. The structural checks below run first so a wiring mistake is
// distinguishable from the unimplemented path.
func (v Verifier) CheckEvidence(id platform.Identity) error {
	if id.Platform != platform.PlatformAlibabaCloud {
		return fmt.Errorf("expected platform %q, got %q", platform.PlatformAlibabaCloud, id.Platform)
	}
	if len(id.Evidence) == 0 {
		return errors.New("alicloud attestation has no evidence")
	}
	if sha256.Sum256(id.Evidence) != id.EvidenceHash {
		return errors.New("alicloud evidence hash mismatch")
	}
	return fmt.Errorf("alicloud evidence verification is not implemented: %w", platform.ErrAttestationNotImplemented)
}

// CheckEvidenceForDeployment is CheckEvidence. Until the evidence path is
// implemented there is no deployment binding to assert either.
func (v Verifier) CheckEvidenceForDeployment(id platform.Identity, _ [32]byte) error {
	return v.CheckEvidence(id)
}
