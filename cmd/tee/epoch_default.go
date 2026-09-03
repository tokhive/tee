//go:build !sevsnp

package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// buildEpoch assembles the attested signing epoch for the selected platform.
//
// The default (untagged) build carries only the simulated software epoch, so
// the local simulation binary stays lean and its CLI stays clean — importing
// the real SEV-SNP stack would drag in the AWS guest toolchain and a global
// flag from go-sev-guest. Cloud deployments compile with `-tags sevsnp`, which
// adds the real adapter via epoch_sevsnp.go.
func buildEpoch(platformName string) (platform.Epoch, error) {
	if platformName == "sevsnp" {
		return nil, fmt.Errorf("sevsnp support is not in this binary; rebuild with `-tags sevsnp` (requires an AWS SEV-SNP guest)")
	}
	return buildSimulatedEpoch()
}
