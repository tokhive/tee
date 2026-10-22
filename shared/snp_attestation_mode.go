package shared

import (
	"fmt"
	"os"
)

const snpAttestationTypeEnv = "SNP_ATTESTATION_TYPE"

// CurrentSNPAttestationType is SEV2 by default for old images and development.
// New signed images bake secure-boot into the loader environment, making the
// evidence format and registration type part of the R-authorized base.
func CurrentSNPAttestationType() string {
	if os.Getenv(snpAttestationTypeEnv) == AttestationTypeSecureBoot {
		return AttestationTypeSecureBoot
	}
	return AttestationTypeSEVSNP
}

func secureBootAttestationEnabled() bool {
	return CurrentSNPAttestationType() == AttestationTypeSecureBoot
}

// ValidateSNPAttestationType rejects misspelled or unknown explicit modes. An
// unset value remains the backwards-compatible SEV2 default.
func ValidateSNPAttestationType() error {
	switch value := os.Getenv(snpAttestationTypeEnv); value {
	case "", AttestationTypeSEVSNP, AttestationTypeSecureBoot:
		return nil
	default:
		return fmt.Errorf("%s must be %q or %q (got %q)", snpAttestationTypeEnv, AttestationTypeSEVSNP, AttestationTypeSecureBoot, value)
	}
}
