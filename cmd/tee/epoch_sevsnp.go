//go:build sevsnp

package main

import (
	"context"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp"
)

// buildEpoch assembles the attested signing epoch for the selected platform.
//
// This file is compiled only with `-tags sevsnp`, which is how a real enclave
// deployment builds the TEE: the AWS SEV-SNP adapter self-verifies its RA-TLS
// identity and fails fast with a descriptive error on any host that is not an
// SEV-SNP AWS guest. The simulated branch stays available so one binary can
// run both the hermetic local sim and the cloud build.
//
// The policy-set hash is bound into the simulated epoch's evidence. On a real
// SEV-SNP host the whitelist ships inside the measured image, so the hardware
// measurement covers it by construction; the parameter is threaded through for
// API symmetry and is not otherwise used by the sevsnp branch.
func buildEpoch(platformName string, policySetHash [32]byte) (platform.Epoch, error) {
	if platformName == "sevsnp" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		adapter, err := sevsnp.NewAWS(ctx, sevsnp.Config{
			Role: envOr("TOKENHIVE_TEE_ROLE", "tokenhive-tee"),
		})
		if err != nil {
			return nil, err
		}
		return adapter.Snapshot(ctx)
	}
	return buildSimulatedEpoch(policySetHash)
}
