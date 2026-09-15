package tencent

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Verifier implements platform.EvidenceVerifier for Tencent Cloud confidential
// computing.
//
// STATUS: SKELETON. This deliberately refuses every tencent receipt with
// platform.ErrAttestationNotImplemented. Implementing CheckEvidence requires
// validating Tencent's remote-attestation protocol — for an SGX instance the
// ECDSA quote chain against Tencent's attestation service (or Intel PCCS), for
// a TDX guest the TDX quote, for an SEV-SNP guest the AMD report via the same
// offline go-sev-guest path the AWS adapter uses — and pinning the trusted
// measured image. Until that lands, no tencent receipt may verify, which is
// exactly what this code enforces.
type Verifier struct{}

// Platform reports the Tencent Cloud platform string.
func (v Verifier) Platform() string { return platform.PlatformTencentCloud }

// CheckEvidence refuses the attestation: the tencent evidence path is not
// implemented. The structural checks below run first so a wiring mistake is
// distinguishable from the unimplemented path.
func (v Verifier) CheckEvidence(id platform.Identity) error {
	if id.Platform != platform.PlatformTencentCloud {
		return fmt.Errorf("expected platform %q, got %q", platform.PlatformTencentCloud, id.Platform)
	}
	if len(id.Evidence) == 0 {
		return errors.New("tencent attestation has no evidence")
	}
	if sha256.Sum256(id.Evidence) != id.EvidenceHash {
		return errors.New("tencent evidence hash mismatch")
	}
	return fmt.Errorf("tencent evidence verification is not implemented: %w", platform.ErrAttestationNotImplemented)
}

// CheckEvidenceForDeployment is CheckEvidence. Until the evidence path is
// implemented there is no deployment binding to assert either.
func (v Verifier) CheckEvidenceForDeployment(id platform.Identity, _ [32]byte) error {
	return v.CheckEvidence(id)
}
