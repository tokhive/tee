package shared

// Attestation types carried across the client, TEE, and router boundaries.
const (
	AttestationTypeCS         = "cs"
	AttestationTypeSEVSNP     = "sev-snp"
	AttestationTypeSecureBoot = "secure-boot"
)

// AttestationReport represents a generic attestation envelope with runtime signing key
// Type: "gcp" (Google Confidential VM)
// Report: raw provider-specific attestation bytes
// SigningKey: TEE_T runtime ETH address to be used by clients
type AttestationReport struct {
	Type       string `json:"type"` // "gcp"
	Report     []byte `json:"report"`
	SigningKey []byte `json:"signing_key"`
}
