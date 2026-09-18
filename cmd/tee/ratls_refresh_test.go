package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
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
			got := nextRefreshDelay(context.Background(), refresher, true, rootShared.NewNopLogger())
			if !test.want(got) {
				t.Fatalf("nextRefreshDelay = %s, want %s", got, test.wantWhy)
			}
		})
	}

	t.Run("a failed snapshot retries on the floor", func(t *testing.T) {
		refresher := &fakeRefresher{err: platform.ErrNotReady}
		if got := nextRefreshDelay(context.Background(), refresher, true, rootShared.NewNopLogger()); got != minRefreshFloor {
			t.Fatalf("nextRefreshDelay = %s, want %s so an unhealthy adapter is retried promptly", got, minRefreshFloor)
		}
	})

	// The publication half can fail on its own: Refresh rotates the listener's
	// key successfully, then the epoch never reaches the signer. The evidence the
	// current signer names is then the previous epoch's — good for about the
	// margin, not for the ceiling — so a cadence that trusted the fresh-looking
	// evidence would leave the TEE signing receipts that resolve to stale proof.
	t.Run("a failed publication retries on the floor although the evidence looks fresh", func(t *testing.T) {
		refresher := &fakeRefresher{snapshot: fakeEpoch(nitroAttestation(t, time.Now().Add(10*time.Hour)))}
		if got := nextRefreshDelay(context.Background(), refresher, false, rootShared.NewNopLogger()); got != minRefreshFloor {
			t.Fatalf("nextRefreshDelay = %s, want %s after a publication that did not land", got, minRefreshFloor)
		}
	})
}

// TestAttestationExpiryReportsWhetherItTrackedTheLeaf pins the flag the
// cadence logs on. An AWS evidence's deadline comes from its NitroTPM leaf and
// is adaptive; anything else falls back to the fixed TTL, and the loop has to
// be able to announce that instead of looking like a healthy schedule.
func TestAttestationExpiryReportsWhetherItTrackedTheLeaf(t *testing.T) {
	tracked := nitroAttestation(t, time.Now().Add(3*time.Hour))
	if _, ok := rootShared.SNPAttestationExpiryFromLeaf(tracked); !ok {
		t.Fatal("AWS evidence reported an untracked expiry")
	}
	if _, ok := rootShared.SNPAttestationExpiryFromLeaf([]byte("not-an-aws-envelope")); ok {
		t.Fatal("non-AWS evidence reported a tracked expiry")
	}
}

// TestPublishEpochAdoptsAndPublishesRotatedEpoch covers the wiring the
// deployment depends on: one rotation must move the receipt signer to the new
// attested key AND leave the new evidence where a hash-only receipt can resolve
// it. Either half alone is a broken deployment — a signer the Hub cannot match
// to evidence it is willing to accept.
func TestPublishEpochAdoptsAndPublishesRotatedEpoch(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	startup := fakeEpoch([]byte("startup-evidence"))
	runtime := newTestRuntime(t, startup, false)
	before := runtime.get()

	rotated := fakeEpoch(nitroAttestation(t, time.Now().Add(3*time.Hour)))
	refresher := &fakeRefresher{snapshot: rotated, serverTLS: fakeServerTLS(t, "rotated-ra-tls-leaf")}
	if err := publishOnce(refresher, runtime); err != nil {
		t.Fatalf("publish rotated epoch: %v", err)
	}

	if runtime.get() == before {
		t.Fatal("rotation did not reach the service that signs receipts")
	}
	if runtime.get() == nil {
		t.Fatal("rotation left the runtime with no service")
	}

	// The identity file is what an auditor reads off the instance; it has to
	// describe the key the receipts now carry, not the one the process booted on.
	if got := readPersistedIdentity(t, simDir); got.KeyID != rotated.Identity().KeyID {
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

	// And the published leaf follows the rotation. It is the file an operator (or
	// tooling) reads to learn which certificate the listener presents, so a
	// startup-only copy would keep answering with a key this process no longer
	// holds — for the whole life of a process whose listener rotates.
	leaf, err := os.ReadFile(filepath.Join(simDir, shared.MTLSServerCertPath))
	if err != nil {
		t.Fatalf("read published RA-TLS leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(pemBlock(t, leaf))
	if err != nil {
		t.Fatalf("parse published RA-TLS leaf: %v", err)
	}
	if parsed.Subject.CommonName != "rotated-ra-tls-leaf" {
		t.Fatalf("published leaf is %q, want the rotated epoch's certificate", parsed.Subject.CommonName)
	}
}

// pemBlock decodes the single PEM block a published certificate file holds.
func pemBlock(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("published RA-TLS leaf is not PEM")
	}
	return block.Bytes
}

// fakeServerTLS mints the self-signed RA-TLS leaf a rotated epoch would publish,
// so the write that follows a rotation can be observed on disk.
func fakeServerTLS(t *testing.T, commonName string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
}

// TestPublishEpochAdoptsWhenTheLeafCannotBePublished: the published leaf and
// identity are diagnostics — files an operator, or the simulation's pin mode,
// reads — so a rotation that cannot rewrite them still adopts. Refusing would
// wedge the signer: the listener has already rotated by the time a refresh
// returns, and the process would go on signing under the key the Hub no longer
// sees on the wire.
func TestPublishEpochAdoptsWhenTheLeafCannotBePublished(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	runtime := newTestRuntime(t, fakeEpoch([]byte("startup-evidence")), false)
	before := runtime.get()

	rotated := fakeEpoch([]byte("rotated-evidence"))
	// A TLS config with no certificate: there are no leaf bytes to write, which
	// is how a publication failure reaches the log.
	refresher := &fakeRefresher{snapshot: rotated, serverTLS: &tls.Config{}}
	if err := publishOnce(refresher, runtime); err != nil {
		t.Fatalf("publish rotated epoch: %v", err)
	}
	if runtime.get() == before {
		t.Fatal("a leaf that could not be published stopped the rotation from signing")
	}
	if got := readPersistedIdentity(t, simDir); got.KeyID != rotated.Identity().KeyID {
		t.Fatal("persisted identity does not name the epoch that is signing")
	}
}

// TestPublishEpochSkipsTheStoreForInlineReceipts: an inline receipt carries its
// own evidence, so a store entry would be a file nothing resolves. Only the
// hash-only form — the one with a hash to look up — writes to it.
func TestPublishEpochSkipsTheStoreForInlineReceipts(t *testing.T) {
	t.Setenv("TOKENHIVE_SIM_DIR", t.TempDir())

	runtime := newTestRuntime(t, fakeEpoch([]byte("startup-evidence")), true)
	rotated := fakeEpoch([]byte("rotated-evidence"))
	refresher := &fakeRefresher{snapshot: rotated, serverTLS: fakeServerTLS(t, "rotated-ra-tls-leaf")}
	if err := publishOnce(refresher, runtime); err != nil {
		t.Fatalf("publish rotated epoch: %v", err)
	}

	store, err := evidence.NewStore(shared.EvidenceDir())
	if err != nil {
		t.Fatal(err)
	}
	if store.Has(rotated.Identity()) {
		t.Fatal("the store holds evidence no verifier would resolve for an inline receipt")
	}
}

// TestPublishEpochKeepsSigningWhenEvidenceCannotBePublished is the fail-closed
// half. A rotated key that the deployment cannot publish evidence for would
// sign receipts nobody can verify, so the rotation must be abandoned whole: the
// previous service keeps signing, and it keeps signing under the epoch whose
// evidence IS resolvable.
func TestPublishEpochKeepsSigningWhenEvidenceCannotBePublished(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	startup := fakeEpoch([]byte("startup-evidence"))
	runtime := newTestRuntime(t, startup, false)
	before := runtime.get()

	// Evidence that does not hash to the identity's EvidenceHash: the store
	// refuses it, which is how a half-built epoch reaches adopt in practice.
	unpublishable := fakeEpoch([]byte("startup-evidence"))
	unpublishable.id.Evidence = []byte("rotated-evidence")
	refresher := &fakeRefresher{snapshot: unpublishable}
	if err := publishOnce(refresher, runtime); err == nil {
		t.Fatal("published an epoch whose evidence could not be written")
	}

	if runtime.get() != before {
		t.Fatal("runtime adopted an epoch whose evidence could not be published")
	}
	// Evidence is written first precisely so its failure cannot leave a later
	// file — the identity an auditor reads — describing an epoch that never
	// signed anything.
	assertIdentityNotRotated(t, simDir, unpublishable.Identity())
}

// assertIdentityNotRotated fails when a refused rotation left tee_identity.json
// naming the epoch it refused to adopt.
func assertIdentityNotRotated(t *testing.T, simDir string, rotated platform.Identity) {
	t.Helper()
	if got := readPersistedIdentity(t, simDir); got.KeyID == rotated.KeyID {
		t.Fatal("a refused rotation left tee_identity.json naming the epoch that never started signing")
	}
}

// readPersistedIdentity reads the identity file an auditor inspects, or a zero
// identity when the process never wrote one.
func readPersistedIdentity(t *testing.T, simDir string) platform.Identity {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(simDir, "tee_identity.json"))
	if errors.Is(err, os.ErrNotExist) {
		return platform.Identity{}
	}
	if err != nil {
		t.Fatalf("read tee identity: %v", err)
	}
	var id platform.Identity
	if err := json.Unmarshal(b, &id); err != nil {
		t.Fatalf("decode tee identity: %v", err)
	}
	return id
}

// publishOnce drives the publication half of one refresh tick. A tick reaches
// here after the adapter has already adopted the rotated epoch (Refresh
// publishes before returning), so this is exactly the step that has to bring the
// signer and every published file along with it. The loop around it is Go timer
// machinery, not the logic under test; runEpochRefresh deliberately skips the
// priming call it would otherwise get (see shared.RunRATLSRefresh).
func publishOnce(refresher epochRefresher, runtime *serviceRuntime) error {
	return publishEpoch(context.Background(), refresher, runtime)
}

// TestAdoptPublishesTheSignerToTheLiveCell: adopting a rotated epoch must move
// the live signer sessions sign with, not just the service pointer new
// requests resolve. Otherwise a rotation fixes the listener while every
// already-open session keeps finishing under the expired key.
func TestAdoptPublishesTheSignerToTheLiveCell(t *testing.T) {
	t.Setenv("TOKENHIVE_SIM_DIR", t.TempDir())

	runtime := newTestRuntime(t, fakeEpoch([]byte("startup-evidence")), false)
	cell := &atomic.Pointer[proof.Signer]{}
	runtime.template.SignerCell = cell

	rotated := fakeEpoch(nitroAttestation(t, time.Now().Add(3*time.Hour)))
	refresher := &fakeRefresher{snapshot: rotated, serverTLS: fakeServerTLS(t, "rotated-ra-tls-leaf")}
	if err := publishOnce(refresher, runtime); err != nil {
		t.Fatalf("publish rotated epoch: %v", err)
	}
	got := cell.Load()
	if got == nil {
		t.Fatal("adopt left the live signer cell empty")
	}
	if got.Epoch().Identity().KeyID != rotated.Identity().KeyID {
		t.Fatal("live signer still names the opening epoch after a rotation")
	}
}

// newTestRuntime builds the smallest real service: the runtime's own logic is
// what is under test, so the transport never runs and the policy is never
// consulted. includeEvidence picks the receipt form the runtime publishes for;
// the hash-only form is the one that needs the evidence store.
func newTestRuntime(t *testing.T, epoch platform.Epoch, includeEvidence bool) *serviceRuntime {
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
	template.Signer.IncludeEvidence = includeEvidence
	runtime, err := newServiceRuntime(template, epoch, nil, rootShared.NewNopLogger())
	if err != nil {
		t.Fatalf("build service runtime: %v", err)
	}
	return runtime
}

type fakeRefresher struct {
	snapshot  platform.Epoch
	err       error
	serverTLS *tls.Config
}

func (f *fakeRefresher) Refresh(context.Context) error { return nil }
func (f *fakeRefresher) Snapshot(context.Context) (platform.Epoch, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.snapshot, nil
}

// ServerTLSConfig is nil unless a test hands over a leaf, which is the "nothing
// to publish" case the rotation logs about and signs through.
func (f *fakeRefresher) ServerTLSConfig() *tls.Config { return f.serverTLS }

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
