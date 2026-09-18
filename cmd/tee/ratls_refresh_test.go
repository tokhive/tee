package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// TestNextRefreshDelayTracksTheNitroTPMLeaf pins the cadence to the thing that
// actually expires. The failure this guards against is subtle: a TEE whose
// refresh cadence is the fixed two-hour ceiling looks correct against a
// three-hour NitroTPM leaf and then silently serves stale evidence on any day
// AWS issues a shorter one, so the adaptive branch has to be exercised with a
// leaf that is inside the cap.
func TestNextRefreshDelayTracksTheNitroTPMLeaf(t *testing.T) {
	tests := []struct {
		name     string
		notAfter time.Time
		want     func(time.Duration) bool
		wantWhy  string
	}{
		{
			name:     "long-lived leaf is capped at the SNP ceiling",
			notAfter: time.Now().Add(10 * time.Hour),
			want:     func(d time.Duration) bool { return d == rootShared.RATLSRefreshIntervalSNP },
			wantWhy:  "a ten-hour leaf must not cause ten-hour churn",
		},
		{
			name:     "short-lived leaf drives the cadence instead of the ceiling",
			notAfter: time.Now().Add(time.Hour),
			want:     func(d time.Duration) bool { return d > 25*time.Minute && d < 30*time.Minute },
			wantWhy:  "refresh 30 minutes before the leaf expires, not at the two-hour mark",
		},
		{
			name:     "an already-expired leaf retries on the floor",
			notAfter: time.Now().Add(-2 * time.Hour),
			want:     func(d time.Duration) bool { return d == minRefreshFloor },
			wantWhy:  "a negative delay must not become a spin loop",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			refresher := &fakeRefresher{snapshot: fakeEpoch(nitroAttestation(t, test.notAfter))}
			got := nextRefreshDelay(context.Background(), refresher)
			if !test.want(got) {
				t.Fatalf("nextRefreshDelay = %s, want %s", got, test.wantWhy)
			}
		})
	}

	t.Run("a failed snapshot retries on the floor", func(t *testing.T) {
		refresher := &fakeRefresher{err: platform.ErrNotReady}
		if got := nextRefreshDelay(context.Background(), refresher); got != minRefreshFloor {
			t.Fatalf("nextRefreshDelay = %s, want %s so an unhealthy adapter is retried promptly", got, minRefreshFloor)
		}
	})
}

// TestRunEpochRefreshAdoptsAndPublishesRotatedEpoch covers the wiring the
// deployment depends on: one rotation must move the receipt signer to the new
// attested key AND leave the new evidence where a hash-only receipt can resolve
// it. Either half alone is a broken deployment — a signer the Hub cannot match
// to evidence it is willing to accept.
func TestRunEpochRefreshAdoptsAndPublishesRotatedEpoch(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	startup := fakeEpoch([]byte("startup-evidence"))
	runtime := newTestRuntime(t, startup)
	before := runtime.get()

	rotated := fakeEpoch(nitroAttestation(t, time.Now().Add(3*time.Hour)))
	refresher := &fakeRefresher{snapshot: rotated}
	runRefreshOnce(t, refresher, runtime)

	if runtime.get() == before {
		t.Fatal("rotation did not reach the service that signs receipts")
	}
	if runtime.get() == nil {
		t.Fatal("rotation left the runtime with no service")
	}

	// The identity file is what an auditor reads off the instance; it has to
	// describe the key the receipts now carry, not the one the process booted on.
	var persisted platform.Identity
	b, err := os.ReadFile(filepath.Join(simDir, "tee_identity.json"))
	if err != nil {
		t.Fatalf("read tee identity: %v", err)
	}
	if err := json.Unmarshal(b, &persisted); err != nil {
		t.Fatalf("decode tee identity: %v", err)
	}
	if persisted.KeyID != rotated.Identity().KeyID {
		t.Fatal("persisted identity still names the startup epoch key")
	}

	// A hash-only receipt (the production form) names EvidenceHash; the store is
	// the only thing that turns that hash back into bytes, locally and over
	// /v1/evidence for a Hub on another host.
	store, err := evidence.NewStore(shared.EvidenceDir())
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(rotated.Identity()) {
		t.Fatal("rotated epoch evidence was not published to the evidence store")
	}
}

// TestRunEpochRefreshKeepsSigningWhenEvidenceCannotBePublished is the
// fail-closed half. A rotated key that the deployment cannot publish evidence
// for would sign receipts nobody can verify, so the rotation must be abandoned
// whole: the previous service keeps signing, and it keeps signing under the
// epoch whose evidence IS resolvable.
func TestRunEpochRefreshKeepsSigningWhenEvidenceCannotBePublished(t *testing.T) {
	t.Setenv("TOKENHIVE_SIM_DIR", t.TempDir())

	startup := fakeEpoch([]byte("startup-evidence"))
	runtime := newTestRuntime(t, startup)
	before := runtime.get()

	// Evidence that does not hash to the identity's EvidenceHash: the store
	// refuses it, which is how a half-built epoch reaches adopt in practice.
	unpublishable := fakeEpoch([]byte("startup-evidence"))
	unpublishable.id.Evidence = []byte("rotated-evidence")
	refresher := &fakeRefresher{snapshot: unpublishable}
	runRefreshOnce(t, refresher, runtime)

	if runtime.get() != before {
		t.Fatal("runtime adopted an epoch whose evidence could not be published")
	}
}

// runRefreshOnce drives one iteration of the real refresh loop: a cancelled
// context makes RunRATLSRefresh adopt the current snapshot and return, which is
// exactly the "rotate, then adopt" step a scheduled tick performs.
func runRefreshOnce(t *testing.T, refresher epochRefresher, runtime *serviceRuntime) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runEpochRefresh(ctx, refresher, runtime, rootShared.NewNopLogger())
}

// newTestRuntime builds the smallest real service: the runtime's own logic is
// what is under test, so the transport never runs and the policy is never
// consulted.
func newTestRuntime(t *testing.T, epoch platform.Epoch) *serviceRuntime {
	t.Helper()
	seq, err := tee.NewFileSeqStore(filepath.Join(t.TempDir(), "seqstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatal(err)
	}
	template := tee.Config{
		Policy:    &policy.Policy{},
		Transport: stubTransport{},
		Signer:    proof.NewSigner(epoch),
		Seq:       seq,
		InboxKey:  inbox,
	}
	template.Signer.IncludeEvidence = true
	svc, err := tee.NewService(template)
	if err != nil {
		t.Fatal(err)
	}
	return newServiceRuntime(template, svc)
}

type fakeRefresher struct {
	snapshot platform.Epoch
	err      error
}

func (f *fakeRefresher) Refresh(context.Context) error { return nil }
func (f *fakeRefresher) Snapshot(context.Context) (platform.Epoch, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.snapshot, nil
}

type fakeEpochImpl struct {
	id platform.Identity
}

func fakeEpoch(evidenceBytes []byte) *fakeEpochImpl {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return &fakeEpochImpl{id: platform.Identity{
		Platform:        platform.PlatformAWSSEVSNP,
		AttestationType: rootShared.AttestationTypeSEVSNP,
		ApplicationID:   "snp-app:deadbeef",
		Evidence:        evidenceBytes,
		EvidenceHash:    sha256.Sum256(evidenceBytes),
		PublicKeyDER:    publicKeyDER,
		KeyID:           sha256.Sum256(publicKeyDER),
	}}
}

func (e *fakeEpochImpl) Identity() platform.Identity { return platform.CloneIdentity(e.id) }

func (e *fakeEpochImpl) Sign(domain string, payload []byte) (platform.Signature, error) {
	if len(domain) == 0 {
		return platform.Signature{}, errors.New("empty signing domain")
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.id.KeyID,
		Value:     []byte("signature"),
	}, nil
}

type stubTransport struct{}

func (stubTransport) Do(context.Context, tee.Request, func([]byte) error, ...tee.StartFunc) (tee.Response, error) {
	return tee.Response{}, errors.New("the transport is not exercised by these tests")
}

// nitroAttestation builds the AWS-tagged combined envelope a real TEE's RA-TLS
// leaf carries, with a NitroTPM document whose leaf expires at notAfter.
//
// The document is NOT verified here, and that is the point: SNPNitroLeafNotAfter
// deliberately reads only the expiry of a document the caller just generated, so
// a synthetic one is a faithful input to the cadence. Dropping the AWS tag is
// asserted below — without it the reader must not claim a NitroTPM leaf at all.
func nitroAttestation(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	// X.509 timestamps carry whole seconds, so the round trip through the
	// certificate is what the reader gets back and what the assertion compares.
	notAfter = notAfter.Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "synthetic-nitrotpm-leaf"},
		NotBefore:    notAfter.Add(-3 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := cbor.Marshal(map[string]any{"certificate": der})
	if err != nil {
		t.Fatal(err)
	}
	cose, err := cbor.Marshal([]any{[]byte("protected"), nil, doc, []byte("signature")})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cbor.Marshal(map[string]any{"nitrotpm": cose})
	if err != nil {
		t.Fatal(err)
	}
	// 0x02 is the AWS tag: the reader keys off it, so the untagged form below is
	// not a NitroTPM attestation no matter what it contains.
	tagged := append([]byte{0x02}, envelope...)
	if got, ok := rootShared.SNPNitroLeafNotAfter(tagged); !ok || !got.Equal(notAfter) {
		t.Fatalf("synthetic NitroTPM leaf not readable: got %s ok=%t", got, ok)
	}
	if _, ok := rootShared.SNPNitroLeafNotAfter(envelope); ok {
		t.Fatal("untagged envelope was read as a NitroTPM attestation")
	}
	return tagged
}
