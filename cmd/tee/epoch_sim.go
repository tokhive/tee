package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
)

// buildSimulatedEpoch returns a fresh software attestation epoch whose
// evidence binds the deployment's policy hash — the simulated stand-in for
// "the whitelist is part of the measured configuration". It is shared by the
// default and the sevsnp-tagged builds so that one binary can always run the
// hermetic local simulation.
func buildSimulatedEpoch(policyHash [32]byte) (platform.Epoch, error) {
	epoch, err := simulated.NewDeploymentEpoch(policyHash)
	if err != nil {
		return nil, fmt.Errorf("create sim epoch: %w", err)
	}
	return epoch, nil
}

// buildSimulatedAssembly is the full startup assembly for the simulated
// platform: the software epoch plus the RA-TLS listener presenting its key.
// The epoch is fixed for the process lifetime — software evidence has no
// expiry to stay ahead of — so no Refresher travels with it.
func buildSimulatedAssembly(policyHash [32]byte) (epochAssembly, error) {
	epoch, err := buildSimulatedEpoch(policyHash)
	if err != nil {
		return epochAssembly{}, err
	}
	return epochAssembly{
		Epoch:     epoch,
		ServerTLS: mtls.PlatformServerTLS(epoch),
	}, nil
}
