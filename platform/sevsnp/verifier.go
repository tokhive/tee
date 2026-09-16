package sevsnp

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Verifier implements platform.EvidenceVerifier for AWS SEV-SNP confidential
// VMs. It validates a combined attestation (AMD SEV-SNP report + NitroTPM
// document) through Reclaim's shared verifier, which uses go-sev-guest with the
// embedded AMD root CA bundle (offline, no KDS dependency).
//
// The production evidence path is exercised against real hardware; the trust
// root here is the operator's pinned expected application identity, which must
// name the exact measured enclave image ("snp-app:<sha256 hex>").
type Verifier struct {
	// ExpectedApp is the attested application identity the deployment trusts,
	// formatted "snp-app:<sha256 hex>". Empty disables the assertion, which is
	// appropriate only for development or when the caller binds the image
	// identity separately.
	ExpectedApp string
}

// Platform reports the AWS SEV-SNP platform string.
func (v Verifier) Platform() string { return platform.PlatformAWSSEVSNP }

// CheckEvidence validates inline AWS SEV-SNP attestation evidence: the chip and
// NitroTPM signature chain, the policy and TCB guards, the caller binding, and
// the expected measured image.
func (v Verifier) CheckEvidence(id platform.Identity) error {
	if id.Platform != platform.PlatformAWSSEVSNP {
		return fmt.Errorf("expected platform %q, got %q", platform.PlatformAWSSEVSNP, id.Platform)
	}
	if len(id.Evidence) == 0 {
		return errors.New("aws sev-snp attestation has no evidence")
	}
	if sum := sha256.Sum256(id.Evidence); sum != id.EvidenceHash {
		return errors.New("aws sev-snp evidence hash mismatch")
	}
	// verifyCombined binds the SPKI into the report and proves the NitroTPM
	// document, the AMD policy/TCB, and the cross-cloud measured application
	// identity in one pass. Secure Boot evidence carries a distinct wire tag
	// (the R-signed loader sets SNP_ATTESTATION_TYPE=secure-boot), so dispatch
	// it to the event-log verifier that also proves the R-only boot policy;
	// plain SEV2 evidence goes through the legacy tag.
	var app string
	var err error
	if shared.IsSecureBootAttestation(id.Evidence) {
		app, _, err = shared.VerifyCombinedSecureBootAttestation(id.Evidence, id.PublicKeyDER)
	} else {
		app, _, err = shared.VerifyCombinedSEVSNPAttestation(id.Evidence, id.PublicKeyDER)
	}
	if err != nil {
		return fmt.Errorf("verify aws sev-snp evidence: %w", err)
	}
	if v.ExpectedApp != "" && app != v.ExpectedApp {
		return fmt.Errorf("%w: attested application %q, expected %q",
			proof.ErrAttestationMismatch, app, v.ExpectedApp)
	}
	return nil
}

// CheckEvidenceForDeployment verifies the deployment binding by verifying the
// image. The whitelist is staged into the measured bundle as ./policy, so the
// bundle digest this evidence attests — the attested application identity —
// covers the exact policy bytes the enclave enforces. Rotating the whitelist
// changes that digest; there is no second value left to compare, and the
// supplied digest is therefore not read.
//
// It refuses when no application identity is expected. Without one CheckEvidence
// asserts nothing about which image ran, so nothing would pin the policy either
// and this would accept any whitelist from any enclave — the outcome this method
// exists to prevent.
func (v Verifier) CheckEvidenceForDeployment(id platform.Identity, _ [32]byte) error {
	if v.ExpectedApp == "" {
		return errors.New("aws sev-snp deployment binding requires an expected application identity: the measured bundle is what pins the policy set")
	}
	return v.CheckEvidence(id)
}
