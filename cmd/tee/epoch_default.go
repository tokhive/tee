//go:build !sevsnp

package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
)

// buildEpoch assembles the attested signing epoch and its RA-TLS server TLS
// config for the selected platform.
//
// The default (untagged) build carries only the simulated software epoch, so
// the local simulation binary stays lean and its CLI stays clean — importing
// the real SEV-SNP stack would drag in the AWS guest toolchain and a global
// flag from go-sev-guest. Cloud deployments compile with `-tags sevsnp`
// (real AWS adapter via epoch_sevsnp.go); any other platform name is a
// descriptive error here.
//
// The simulated epoch carries no Refresher: its software evidence has no expiry
// to stay ahead of, so it is fixed for the process lifetime.
func buildEpoch(platformName string, policyHash [32]byte) (epochAssembly, error) {
	if platformName != "simulated" {
		return epochAssembly{}, fmt.Errorf("platform %q is not in this binary; only simulated is built by default (rebuild with `-tags sevsnp` for AWS SEV-SNP)", platformName)
	}
	epoch, err := buildSimulatedEpoch(policyHash)
	if err != nil {
		return epochAssembly{}, err
	}
	return epochAssembly{
		Epoch:     epoch,
		ServerTLS: shared.PlatformServerTLS(epoch),
	}, nil
}
