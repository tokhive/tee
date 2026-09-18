package tee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// nitroEnvelope builds the AWS-tagged combined envelope a real TEE's RA-TLS
// leaf carries, with a NitroTPM document whose leaf expires at notAfter. The
// document is never chain-verified here — SNPAttestationExpiryFromLeaf only
// reads the expiry — so a synthetic one is a faithful input to the freshness
// gate. Times are pinned to baseTime (the service clock in these tests), never
// the wall clock, so the suite does not rot.
func nitroEnvelope(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
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
	return append([]byte{0x02}, envelope...)
}

// epochWithNitroLeaf is newTestEpoch with AWS-tagged evidence expiring at
// notAfter, so the freshness gate has a real deadline to read.
func epochWithNitroLeaf(t *testing.T, notAfter time.Time) *testEpoch {
	t.Helper()
	epoch := newTestEpoch(t)
	evidence := nitroEnvelope(t, notAfter)
	epoch.identity.Evidence = evidence
	epoch.identity.EvidenceHash = sha256.Sum256(evidence)
	return epoch
}

// withSigner swaps the service's receipt signer, keeping everything else from
// the default env (inbox, policy, transport) so the job stays submittable.
func withSigner(epoch *testEpoch) envOption {
	return func(c *Config) { c.Signer = proof.NewSigner(epoch) }
}

// TestExecuteRefusesWhenSignerStale is the fail-closed half of rotation: when
// publishing has been failing so long the signing epoch passed its margin,
// new jobs are refused before they can spend provider work or a sequence
// number — never executed-then-signed-invalid.
func TestExecuteRefusesWhenSignerStale(t *testing.T) {
	env := newTestEnv(t, withSigner(epochWithNitroLeaf(t, baseTime.Add(-time.Hour))))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("Execute with a stale epoch = %v, want %v", err, ErrAttestationStale)
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("refused job reached the provider transport")
	}
	if seq, err := env.service.seq.Next([]byte("openai")); err != nil || seq != 1 {
		t.Fatalf("refused job consumed sequence (next = %d, err = %v), want the series untouched", seq, err)
	}
}

// TestExecuteAdmitsWhenSignerFresh pins the other side: an AWS-tagged epoch
// inside its margin executes normally, so the gate cannot mistake a healthy
// rotation for an outage.
func TestExecuteAdmitsWhenSignerFresh(t *testing.T) {
	epoch := epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))
	env := newTestEnv(t, withSigner(epoch))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("Execute with a fresh epoch = %v, want success", err)
	}
	if result == nil || string(result.Receipt.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("receipt is not signed under the fresh epoch")
	}
}

// TestOpenSessionRefusesWhenSignerStale: opening a session spends a sequence
// number and a provider handshake, so the same refusal applies before either.
func TestOpenSessionRefusesWhenSignerStale(t *testing.T) {
	env := newTestEnv(t, withSigner(epochWithNitroLeaf(t, baseTime.Add(-time.Hour))))
	spec := env.spec(t, nil)
	spec.Session = true
	spec.Method = "GET"

	if _, err := env.service.OpenSession(context.Background(), Job{Spec: spec}); !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("OpenSession with a stale epoch = %v, want %v", err, ErrAttestationStale)
	}
	if seq, err := env.service.seq.Next([]byte("openai")); err != nil || seq != 1 {
		t.Fatalf("refused session consumed sequence (next = %d, err = %v)", seq, err)
	}
}

// TestSessionReceiptFollowsTheLiveSigner: a session opened under one epoch
// finishes under whatever the process serves when it ends. A rotation landing
// mid-session must move the final receipt to the fresh key, not leave it on
// the expired one the session started with.
func TestSessionReceiptFollowsTheLiveSigner(t *testing.T) {
	cell := &atomic.Pointer[proof.Signer]{}
	env := newTestEnv(t, func(c *Config) { c.SignerCell = cell })

	conn := &fakeSessionConn{readData: []byte("stream-bytes"), readErr: io.EOF}
	ss := newCellSession(t, env, cell, conn)
	drainSession(t, ss)

	rotated := epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))
	cell.Store(proof.NewSigner(rotated))

	result, err := ss.Receipt()
	if err != nil {
		t.Fatalf("session Receipt after rotation = %v, want success", err)
	}
	if string(result.Receipt.Receipt.Attestation.KeyID) != string(rotated.identity.KeyID[:]) {
		t.Fatal("session receipt still names the opening epoch after a rotation")
	}
}

// TestSessionReceiptRefusesWhenLiveSignerStale: when the whole pipeline is
// down past its margin even the current key is stale, and an explicit error
// beats a receipt no verifier would accept. The refusal is not cached, so a
// later Receipt after recovery still succeeds.
func TestSessionReceiptRefusesWhenLiveSignerStale(t *testing.T) {
	cell := &atomic.Pointer[proof.Signer]{}
	env := newTestEnv(t, func(c *Config) { c.SignerCell = cell })

	conn := &fakeSessionConn{readData: []byte("stream-bytes"), readErr: io.EOF}
	ss := newCellSession(t, env, cell, conn)
	drainSession(t, ss)

	cell.Store(proof.NewSigner(epochWithNitroLeaf(t, baseTime.Add(-time.Hour))))
	if _, err := ss.Receipt(); !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("session Receipt with a stale live signer = %v, want %v", err, ErrAttestationStale)
	}

	cell.Store(proof.NewSigner(epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))))
	if _, err := ss.Receipt(); err != nil {
		t.Fatalf("session Receipt after recovery = %v, want success", err)
	}
}

// newCellSession assembles a Session like newSessionForTest but on a service
// that follows cell, so tests can rotate the signer mid-session the way the
// refresh loop does.
func newCellSession(t *testing.T, env *testEnv, cell *atomic.Pointer[proof.Signer], conn SessionConn) *Session {
	t.Helper()
	if cell.Load() == nil {
		cell.Store(proof.NewSigner(env.epoch))
	}
	spec := env.spec(t, nil)
	spec.Session = true
	spec.Method = "GET"
	hash, err := spec.Hash()
	if err != nil {
		t.Fatalf("hash spec: %v", err)
	}
	policyHash := make([]byte, 32)
	return &Session{
		svc:       env.service,
		spec:      spec,
		specHash:  hash,
		decision:  policy.Decision{PolicyHash: policyHash},
		seq:       1,
		conn:      conn,
		hasher:    proof.NewStreamingHasher(spec.JobID),
		started:   baseTime.Unix(),
		downLimit: spec.MaxResponseBytes,
	}
}

// TestUntrackedEvidenceNeverGoesStale: evidence without a readable NitroTPM
// leaf (simulated epochs, integration fakes) carries no TEE-side expiry, so
// even a clock far past the fallback TTL must not trip the gate. The fallback
// TTL is a refresh-scheduling aid, not a verdict on serving.
func TestUntrackedEvidenceNeverGoesStale(t *testing.T) {
	signer := proof.NewSigner(newTestEpoch(t))
	farFuture := baseTime.Add(365 * 24 * time.Hour)
	if signerStaleAt(signer, farFuture) {
		t.Fatal("untracked evidence reported stale a year later; only a NitroTPM leaf expiry refuses work")
	}
	if signerStaleAt(signer, baseTime) {
		t.Fatal("untracked evidence reported stale at boot")
	}
}
