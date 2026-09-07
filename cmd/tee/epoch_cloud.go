//go:build cloud && !sevsnp

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/alicloud"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/tencent"
)

// buildEpoch assembles the attested signing epoch and its RA-TLS server TLS
// config for the selected platform.
//
// This file is compiled only with `-tags cloud`, which adds the Alibaba Cloud
// and Tencent Cloud adapter skeletons. Both are SKELETONS: their attestation
// verification is not implemented, so they fail closed on a real cloud guest
// unless -allow-untrusted is passed — in which case they sign with an
// explicitly unattested dev key, wiring tests only. The simulated branch stays
// available so one binary can run both the local sim and the cloud build.
func buildEpoch(platformName string, policySetHash [32]byte, allowUntrusted bool) (platform.Epoch, *tls.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch platformName {
	case "alicloud":
		adapter, err := alicloud.NewAlibabaCloud(alicloud.Config{
			Role:           envOr("TOKENHIVE_TEE_ROLE", "tokenhive-tee"),
			AllowUntrusted: allowUntrusted,
		})
		if err != nil {
			return nil, nil, err
		}
		snapshot, err := adapter.Snapshot(ctx)
		if err != nil {
			return nil, nil, err
		}
		return snapshot, adapter.ServerTLSConfig(), nil

	case "tencent":
		adapter, err := tencent.NewTencentCloud(tencent.Config{
			Role:           envOr("TOKENHIVE_TEE_ROLE", "tokenhive-tee"),
			AllowUntrusted: allowUntrusted,
		})
		if err != nil {
			return nil, nil, err
		}
		snapshot, err := adapter.Snapshot(ctx)
		if err != nil {
			return nil, nil, err
		}
		return snapshot, adapter.ServerTLSConfig(), nil

	case "sevsnp":
		return nil, nil, fmt.Errorf("sevsnp support is not in this binary; rebuild with `-tags sevsnp` (requires an AWS SEV-SNP guest)")
	}
	epoch, err := buildSimulatedEpoch(policySetHash)
	if err != nil {
		return nil, nil, err
	}
	return epoch, shared.PlatformServerTLS(epoch), nil
}
