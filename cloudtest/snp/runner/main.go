// Command snprunner is the app entrypoint the SNP loader boots. It is the
// measured `./app` of the two-tier loader image (see deploy/snp-build.sh).
//
// The loader launches this binary twice on AWS SEV-SNP: once as a root,
// device-owning attestation broker (/dev/sev-guest, /dev/tpm*) and once as the
// unprivileged app connected to it. `RunSNPAttestationBrokerIfRequested`
// handles that split (the same one tee_k/tee_t and tokenhive/cmd/tee use).
//
// As the app, this probe proves the core claim of a real TEE run: that the
// loader correctly exported `SNP_APP_HASH` (= sha256 of the measured bundle)
// and that a generated, self-verified AWS SEV-SNP attestation binds exactly
// that value. It prints a single machine-parseable result line and exits.
//
// This is intentionally narrow: the full mTLS mockprovider topology is already
// exercised end-to-end by the `simulated` cloudtest; this module adds the one
// thing `simulated` cannot — real SNP hardware binding of the app identity.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func main() {
	if broker, err := shared.RunSNPAttestationBrokerIfRequested(); broker {
		if err != nil {
			fmt.Fprintln(os.Stderr, "snp attestation broker failed:", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(runProbe())
}

func runProbe() int {
	logger, err := shared.NewLoggerFromEnv("snprunner")
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger: ", err)
		return 1
	}

	// The recovered app hash must match the loader-exported SNP_APP_HASH. The
	// shared verifier already guarantees the attestation is hardware-signed and
	// targets this process's SPKI; a mismatch here means the loader measured a
	// different bundle than the one the app sees — the exact failure we exist
	// to catch.
	appHash := os.Getenv("SNP_APP_HASH")
	if appHash == "" {
		fmt.Fprintln(os.Stderr, "SNP_TEST_RESULT matched=no reason=SNP_APP_HASH-not-set")
		return 1
	}

	app, attType, verr := verifyAttestation(logger)
	if verr != nil {
		fmt.Fprintln(os.Stderr, "SNP_TEST_RESULT matched=no reason=verify error:", verr)
		return 1
	}
	// The verifier returns the identity in its documented snp-app:<hex> form,
	// while SNP_APP_HASH is the bare loader-exported digest; strip the prefix
	// before comparing.
	recovered := strings.TrimPrefix(app, shared.SEVSNPAppPrefix)
	if !strings.EqualFold(recovered, appHash) {
		fmt.Fprintf(os.Stderr, "SNP_TEST_RESULT matched=no reason=hash-mismatch attestation_type=%s env_hash=%s recovered=%s\n",
			attType, appHash, recovered)
		return 1
	}
	fmt.Printf("SNP_TEST_RESULT matched=yes attestation_type=%s app_hash=%s\n", attType, appHash)
	return 0
}

// verifyAttestation builds the real RA-TLS cert (which embeds the combined AWS
// SEV-SNP attestation — NitroTPM document + SEV report — binding SNP_APP_HASH
// into its report_data) and self-verifies it, returning the app hash the
// hardware actually committed to. Mirrors the tee_k/tee_t SNP_ATTEST_DUMP path.
func verifyAttestation(logger *shared.Logger) (app string, attType string, err error) {
	ratls, err := shared.NewRATLSManager(context.Background(), "tokenhive-snp", nil)
	if err != nil {
		return "", "", fmt.Errorf("ratls init: %w", err)
	}
	app, attType, _, verr := shared.ExtractIdentityFromRATLS(ratls.Snapshot(), logger)
	if verr != nil {
		return "", "", fmt.Errorf("extract identity: %w", verr)
	}
	return app, attType, nil
}
