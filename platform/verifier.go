package platform

// EvidenceVerifier validates a platform attestation against the verifier's own
// trust root.
//
// proof.Verify proves that an attested key produced a signature. That is a
// necessary half of the guarantee, but not sufficient: a verifier must also
// decide that the attestation itself names an image it trusts. That is this
// interface's job. Each attestation platform (the simulated software epoch, the
// AWS SEV-SNP confidential VM, and future cloud adapters) ships one
// implementation that knows how to verify its own evidence format and what its
// own trusted measurement is.
type EvidenceVerifier interface {
	// Platform returns the attestation platform string this verifier accepts,
	// e.g. "simulated" or "aws-sev-snp".
	Platform() string

	// CheckEvidence validates inline attestation evidence in an Identity: it
	// parses the evidence, verifies the trust chain against the verifier's
	// root, and asserts the attested measurement is one the deployment trusts.
	// Evidence must be present (this is the inline, self-contained path).
	CheckEvidence(id Identity) error

	// CheckEvidenceForDeployment is CheckEvidence plus proof that the enclave
	// ran with exactly the given policy-set configuration bound into its
	// evidence. A verifier that knows which whitelist configuration a TEE was
	// deployed with uses this, so the attestation proves not just "the trusted
	// image ran" but "the trusted image ran with this configuration".
	//
	// Platforms whose measurement physically covers the shipped configuration
	// (a real SEV-SNP image bakes its config into the measured bundle) may
	// implement this as CheckEvidence plus a binding assertion, or delegate
	// entirely to CheckEvidence when the measurement already covers it.
	CheckEvidenceForDeployment(id Identity, policySetHash [32]byte) error
}
