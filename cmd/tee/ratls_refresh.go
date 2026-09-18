// RA-TLS epoch refresh for the TokenHive TEE.
//
// The Hub↔TEE channel is mutual TLS, and the TEE's half of it is an attested
// RA-TLS certificate: on AWS SEV-SNP the leaf carries a NitroTPM attestation
// whose chain is signed by AWS and is only valid for hours. A TEE that boots
// once and runs for weeks would therefore hand the Hub a certificate whose
// evidence has expired — the Hub's chain check, and the receipt verifier's, are
// both date-checked, so the deployment would go dark on a schedule.
//
// The rotation itself lives behind the platform adapter (sevsnp.Adapter.Refresh
// rotates the key and re-verifies the resulting epoch in one step). What is
// assembled here is the TEE-specific half: which parts of this process follow
// the rotated epoch, when the next rotation is due, and what has to be durable
// before a rotated key is allowed to sign.
package main

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// epochRefresher is the rotation surface of a platform whose attested epoch
// expires. The AWS SEV-SNP adapter implements it: one Refresh rotates the
// RA-TLS key and re-verifies the resulting epoch before publishing it, so this
// process never signs with a key the platform has not attested to. A nil
// refresher means the epoch is fixed for the process lifetime — the simulation,
// whose software evidence does not expire.
type epochRefresher interface {
	Refresh(context.Context) error
	Snapshot(context.Context) (platform.Epoch, error)
}

// epochAssembly is what buildEpoch assembles for the selected platform: the
// epoch that signs receipts now, the RA-TLS listener configuration presenting
// the matching key, and — where that evidence expires — the adapter that
// rotates both.
type epochAssembly struct {
	Epoch     platform.Epoch
	ServerTLS *tls.Config
	Refresher epochRefresher
}

// minRefreshFloor bounds how soon the adaptive cadence may fire again. It is
// the floor tee_k/tee_t apply too, and it earns its keep after a failed
// rotation: the adapter latches itself unhealthy and Snapshot reports
// ErrNotReady, so without a floor the retry would fall back to the two-hour SNP
// ceiling and a single transient attestation failure would keep the TEE's TLS
// listener closed for the rest of that window.
const minRefreshFloor = 10 * time.Minute

// serviceRuntime is the mutable half of this process. A receipt names the
// attested key that signed it, so a rotation has to reach the service that
// signs. Everything else the service holds — the whitelist, the transport, the
// sequence store, the credential inbox key — is fixed for the process lifetime,
// so a rotation rebuilds the service around a fresh signer rather than
// restructuring any of it. Service is immutable once NewService returns, which
// is what makes publishing the new one a pointer assignment.
type serviceRuntime struct {
	template        tee.Config
	includeEvidence bool

	mu      sync.RWMutex
	current *tee.Service
}

// newServiceRuntime keeps the template every rotation rebuilds from, plus the
// service built for the startup epoch.
func newServiceRuntime(template tee.Config, current *tee.Service) *serviceRuntime {
	return &serviceRuntime{
		template:        template,
		includeEvidence: template.Signer.IncludeEvidence,
		current:         current,
	}
}

// get returns the service signing receipts right now. Handlers go through it on
// every request, so a rotation reaches them without a restart or a reconnect.
func (r *serviceRuntime) get() *tee.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// adopt binds the runtime to an epoch: it builds the service that signs with
// that epoch's key and publishes it. Receipts signed from here on name the key
// the TEE presents on its TLS listener, which is the pairing a verifier checks
// when it resolves a receipt's attestation reference.
func (r *serviceRuntime) adopt(epoch platform.Epoch) error {
	template := r.template
	template.Signer = proof.NewSigner(epoch)
	template.Signer.IncludeEvidence = r.includeEvidence
	next, err := tee.NewService(template)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.current = next
	r.mu.Unlock()
	return nil
}

// runEpochRefresh keeps the attested epoch inside its evidence's validity for as
// long as the process runs, using the shared SEV-SNP cadence: rotate no later
// than SNPRefreshMargin before the NitroTPM leaf's NotAfter, capped at
// RATLSRefreshIntervalSNP so a long-lived leaf does not cause churn, and floored
// at minRefreshFloor.
//
// The credential inbox key is deliberately untouched here. It is generated once
// at startup and never persisted, so a restart — not a rotation — is what makes
// agents re-register; keeping the two independent is what lets a TEE rotate its
// evidence without invalidating the envelopes providers sealed to it.
func runEpochRefresh(ctx context.Context, refresher epochRefresher, runtime *serviceRuntime, logger *rootShared.Logger) {
	adopt := func() error {
		snapshot, err := refresher.Snapshot(ctx)
		if err != nil {
			return err
		}
		identity := snapshot.Identity()
		// Publish the rotated identity before it starts signing: the
		// tee_identity.json an auditor reads has to describe the key the
		// receipts carry.
		if err := shared.WriteTEEIdentity(identity); err != nil {
			return err
		}
		// The evidence store is how a hash-only receipt's EvidenceHash resolves
		// — locally, and over /v1/evidence for a Hub on another host. A rotated
		// epoch that never lands here signs receipts nobody can verify, so this
		// strictly precedes publishing the new signer.
		if err := shared.RecordTEEEvidence(identity); err != nil {
			return err
		}
		return runtime.adopt(snapshot)
	}
	next := func() time.Duration { return nextRefreshDelay(ctx, refresher) }
	// The health tracker is intentionally nil: AttestationHealth exists to
	// self-reset a guest whose attestation device has wedged, and this process
	// has no recovery path to drive. A refresh that keeps failing is logged by
	// the loop and shows up as the Hub losing its TLS peer.
	rootShared.RunRATLSRefresh(ctx, refresher, adopt, next, nil, logger)
}

// nextRefreshDelay picks how long to wait before the next rotation. It reads
// the expiry out of the evidence the TEE is currently presenting, so the cadence
// tracks whatever TTL AWS actually issues rather than a hardcoded guess, and
// clamps the result between the two published bounds: RATLSRefreshIntervalSNP
// caps churn when the leaf is long-lived, and minRefreshFloor keeps a failed
// rotation from waiting out the full ceiling before it retries.
func nextRefreshDelay(ctx context.Context, refresher epochRefresher) time.Duration {
	snapshot, err := refresher.Snapshot(ctx)
	if err != nil {
		// The previous rotation failed (or one is in flight) and the adapter is
		// not admitting anything until it succeeds.
		return minRefreshFloor
	}
	expiry := rootShared.SNPAttestationExpiry(snapshot.Identity().Evidence)
	return max(min(time.Until(expiry), rootShared.RATLSRefreshIntervalSNP), minRefreshFloor)
}
