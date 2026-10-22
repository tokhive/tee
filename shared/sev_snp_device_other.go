//go:build !linux && !mobile

package shared

import "fmt"

// IsSEVSNPMode is always false off Linux — the SEV-SNP guest device is a Linux
// kernel interface. Lets client/dev builds on macOS compile the verify path.
func IsSEVSNPMode() bool { return false }

// GenerateSEVSNPAttestation is unavailable off Linux; TEEs only run on Linux.
func GenerateSEVSNPAttestation(reportData [64]byte) ([]byte, error) {
	return nil, fmt.Errorf("SEV-SNP attestation generation is only supported on Linux")
}

// GenerateCombinedGCPAttestation is unavailable off Linux.
func GenerateCombinedGCPAttestation(spkiDER, appHash []byte) ([]byte, error) {
	return nil, fmt.Errorf("combined GCP attestation generation is only supported on Linux")
}

// GenerateCombinedAWSAttestation is unavailable off Linux.
func GenerateCombinedAWSAttestation(spkiDER, appHash []byte) ([]byte, error) {
	return nil, fmt.Errorf("combined AWS attestation generation is only supported on Linux")
}

// GenerateSEVSNPNonceAttestation is unavailable off Linux.
func GenerateSEVSNPNonceAttestation(nonces []string) ([]byte, error) {
	return nil, fmt.Errorf("SEV-SNP nonce attestation generation is only supported on Linux")
}

// IsAWSSEVSNP is always false off Linux.
func IsAWSSEVSNP() bool { return false }
