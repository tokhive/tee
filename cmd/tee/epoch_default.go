//go:build !sevsnp && !cloud

package main

import (
	"crypto/tls"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// buildEpoch assembles the attested signing epoch and its RA-TLS server TLS
// config for the selected platform.
//
// The default (untagged) build carries only the simulated software epoch, so
// the local simulation binary stays lean and its CLI stays clean — importing
// the real SEV-SNP stack would drag in the AWS guest toolchain and a global
// flag from go-sev-guest. Cloud deployments compile with `-tags sevsnp` (real
// AWS adapter via epoch_sevsnp.go) or `-tags cloud` (Alibaba/Tencent adapter
// skeletons via epoch_cloud.go); each of those names is a descriptive error
// here.
func buildEpoch(platformName string, policySetHash [32]byte, allowUntrusted bool) (platform.Epoch, *tls.Config, error) {
	switch platformName {
	case "sevsnp":
		return nil, nil, fmt.Errorf("sevsnp support is not in this binary; rebuild with `-tags sevsnp` (requires an AWS SEV-SNP guest)")
	case "alicloud":
		return nil, nil, fmt.Errorf("alicloud support is not in this binary; rebuild with `-tags cloud`")
	case "tencent":
		return nil, nil, fmt.Errorf("tencent support is not in this binary; rebuild with `-tags cloud`")
	}
	epoch, err := buildSimulatedEpoch(policySetHash)
	if err != nil {
		return nil, nil, err
	}
	return epoch, shared.PlatformServerTLS(epoch), nil
}
