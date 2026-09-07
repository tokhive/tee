// Package alicloud is the TokenHive platform adapter skeleton for Alibaba
// Cloud confidential computing (encrypted-computing Intel SGX instances and
// confidential VMs backed by Intel TDX / AMD SEV-SNP).
//
// STATUS: SKELETON. The host detection and the platform.Epoch plumbing are
// implemented and compile in every build; the ATTESTATION VERIFICATION IS NOT.
// Alibaba's remote-attestation protocol (SGX ECDSA quotes via its attestation
// service, TDX quotes, or an SEV-SNP report) must be validated and wired into
// the Verifier before this platform may admit trusted work. Until then:
//
//   - NewAlibabaCloud refuses to start on a real host unless Config.AllowUntrusted
//     is set, and AllowUntrusted is explicitly a wiring-only mode that signs with
//     an UNATTESTED software key;
//   - Verifier.CheckEvidence refuses every alicloud receipt with
//     platform.ErrAttestationNotImplemented.
//
// Fail-closed by construction: nothing here can be mistaken for trusted
// hardware.
package alicloud

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/dev"
)

// Config controls the identity emitted by the Alibaba Cloud adapter.
type Config struct {
	// Role names the deployment role, e.g. "tokenhive-tee". Kept for API
	// symmetry with the sevsnp adapter and for the future attestation binding.
	Role string

	// AllowUntrusted admits work with a software-minted, UNATTESTED identity.
	// It exists ONLY to exercise the wiring end to end on an Alibaba instance
	// before the attestation path is implemented. Receipts it signs carry the
	// "alicloud" platform string but are refused by Verifier by design. Never
	// set this in production.
	AllowUntrusted bool

	// detect overrides host detection; used by tests.
	detect func() (teeTech string, ok bool)
}

// Adapter keeps the current dev epoch and its (unattested) server TLS config.
type Adapter struct {
	role string

	mu      sync.RWMutex
	current platform.Epoch
	healthy bool
}

// NewAlibabaCloud detects the host and returns an adapter for an Alibaba Cloud
// confidential-computing guest. It fails closed: without AllowUntrusted it
// refuses to run because the attestation path is not yet implemented.
func NewAlibabaCloud(config Config) (*Adapter, error) {
	return newAdapter(config, hostTEETech)
}

func newAdapter(config Config, detect func() (string, bool)) (*Adapter, error) {
	config.Role = strings.TrimSpace(config.Role)
	if detect == nil {
		detect = hostTEETech
	}
	tech, ok := detect()
	if !ok {
		return nil, errors.New("alicloud adapter requires an Alibaba Cloud confidential-computing guest (SGX / TDX / SEV-SNP device not found)")
	}
	if !config.AllowUntrusted {
		return nil, fmt.Errorf("alicloud attestation verification is not implemented; refusing to start (%s detected). Rebuild with -tags cloud and set AllowUntrusted ONLY for wiring tests: %w", tech, platform.ErrAttestationNotImplemented)
	}
	epoch, err := dev.NewEpoch(platform.PlatformAlibabaCloud, "tokenhive-tee")
	if err != nil {
		return nil, fmt.Errorf("mint alicloud dev epoch: %w", err)
	}
	return &Adapter{role: config.Role, current: epoch, healthy: true}, nil
}

// Healthy reports whether the adapter is admitting work. True only in the
// AllowUntrusted wiring mode; the skeleton never reports healthy for trust.
func (a *Adapter) Healthy() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// ServerTLSConfig returns the (unattested) server TLS config of the dev epoch,
// or ErrNotReady when the adapter is not admitting work. A Hub pinning this
// certificate pins the dev key, never a hardware-attested RA-TLS leaf.
func (a *Adapter) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			a.mu.RLock()
			defer a.mu.RUnlock()
			if !a.healthy || a.current == nil {
				return nil, platform.ErrNotReady
			}
			if s, ok := a.current.(interface{ ServerTLSConfig() *tls.Config }); ok {
				cfg := s.ServerTLSConfig()
				if cfg.GetCertificate != nil {
					return cfg.GetCertificate(nil)
				}
				if len(cfg.Certificates) > 0 {
					c := cfg.Certificates[0]
					return &c, nil
				}
			}
			return nil, platform.ErrNotReady
		},
	}
}

// Snapshot returns the current epoch. Without AllowUntrusted the adapter is
// never constructed, so this only ever returns the dev epoch.
func (a *Adapter) Snapshot(ctx context.Context) (platform.Epoch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.healthy || a.current == nil {
		return nil, platform.ErrNotReady
	}
	return a.current, nil
}

// Refresh is a no-op in the skeleton: there is no key rotation without an
// attested epoch to rotate. Present for the platform.Adapter interface.
func (a *Adapter) Refresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

var _ platform.Adapter = (*Adapter)(nil)
