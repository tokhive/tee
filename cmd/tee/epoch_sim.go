package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
)

// buildSimulatedEpoch returns a fresh software attestation epoch. It is shared
// by the default and the sevsnp-tagged builds so that one binary can always
// run the hermetic local simulation.
func buildSimulatedEpoch() (platform.Epoch, error) {
	epoch, err := simulated.NewEpoch()
	if err != nil {
		return nil, fmt.Errorf("create sim epoch: %w", err)
	}
	return epoch, nil
}
