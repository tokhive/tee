package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
)

// buildSimulatedEpoch returns a fresh software attestation epoch whose
// evidence binds the deployment's policy-set hash — the simulated stand-in for
// "the whitelist is part of the measured configuration". It is shared by the
// default and the sevsnp-tagged builds so that one binary can always run the
// hermetic local simulation.
func buildSimulatedEpoch(policySetHash [32]byte) (platform.Epoch, error) {
	epoch, err := simulated.NewDeploymentEpoch(policySetHash)
	if err != nil {
		return nil, fmt.Errorf("create sim epoch: %w", err)
	}
	return epoch, nil
}
