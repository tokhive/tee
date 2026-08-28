//go:build !mobile

package sevsnp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

func TestNewAWSRequiresAWSSEVSNP(t *testing.T) {
	tests := []struct {
		name  string
		isSNP bool
		isAWS bool
	}{
		{name: "not SNP", isSNP: false, isAWS: true},
		{name: "not AWS", isSNP: true, isAWS: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := testDependencies(newFakeManager(t))
			deps.isSEVSNP = func() bool { return test.isSNP }
			deps.isAWS = func() bool { return test.isAWS }
			if _, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, deps); err == nil {
				t.Fatal("newAWS succeeded on the wrong platform")
			}
		})
	}
}

func TestSnapshotBindsEvidenceAndSignaturesToOneEpoch(t *testing.T) {
	manager := newFakeManager(t)
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}

	epoch, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	identity := epoch.Identity()
	if identity.Platform != platform.PlatformAWSSEVSNP {
		t.Fatalf("platform = %q", identity.Platform)
	}
	if identity.AttestationType != shared.AttestationTypeSEVSNP {
		t.Fatalf("attestation type = %q", identity.AttestationType)
	}
	if string(identity.Evidence) != "verified-evidence" {
		t.Fatalf("evidence = %q", identity.Evidence)
	}

	signature, err := epoch.Sign("tokenhive.receipt.v1", []byte("receipt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.VerifySignature(identity, "tokenhive.receipt.v1", []byte("receipt"), signature); err != nil {
		t.Fatalf("epoch signature did not verify against attested identity: %v", err)
	}

	identity.Evidence[0] ^= 0xff
	identity.PublicKeyDER[0] ^= 0xff
	unchanged := epoch.Identity()
	if string(unchanged.Evidence) != "verified-evidence" {
		t.Fatalf("cached evidence was mutated through Identity: %q", unchanged.Evidence)
	}
	if err := platform.VerifySignature(unchanged, "tokenhive.receipt.v1", []byte("receipt"), signature); err != nil {
		t.Fatalf("cached public key was mutated through Identity: %v", err)
	}
}

func TestRefreshPublishesOneNewVerifiedEpoch(t *testing.T) {
	manager := newFakeManager(t)
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}
	before, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	manager.next = newFakeSnapshot(t, "next-evidence")
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentity := before.Identity()
	afterIdentity := after.Identity()
	if beforeIdentity.KeyID == afterIdentity.KeyID {
		t.Fatal("refresh did not publish a new attested key")
	}
	if string(afterIdentity.Evidence) != "next-evidence" {
		t.Fatalf("refreshed evidence = %q", afterIdentity.Evidence)
	}

	beforeSignature, err := before.Sign("tokenhive.receipt.v1", []byte("before"))
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.VerifySignature(beforeIdentity, "tokenhive.receipt.v1", []byte("before"), beforeSignature); err != nil {
		t.Fatalf("old epoch signature did not remain bound to old identity: %v", err)
	}
	if err := platform.VerifySignature(afterIdentity, "tokenhive.receipt.v1", []byte("before"), beforeSignature); err == nil {
		t.Fatal("old epoch signature verified against refreshed identity")
	}
	afterSignature, err := after.Sign("tokenhive.receipt.v1", []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.VerifySignature(afterIdentity, "tokenhive.receipt.v1", []byte("after"), afterSignature); err != nil {
		t.Fatalf("new epoch signature did not verify against refreshed identity: %v", err)
	}
}

func TestRefreshFailureClosesTLSAdmission(t *testing.T) {
	manager := newFakeManager(t)
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}
	manager.refreshErr = errors.New("attestation device unavailable")

	if err := adapter.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded")
	}
	if adapter.Healthy() {
		t.Fatal("adapter remained healthy after refresh failure")
	}
	if _, err := adapter.Snapshot(context.Background()); !errors.Is(err, platform.ErrNotReady) {
		t.Fatalf("Snapshot error = %v, want ErrNotReady", err)
	}
	if _, err := adapter.ServerTLSConfig().GetCertificate(nil); !errors.Is(err, platform.ErrNotReady) {
		t.Fatalf("GetCertificate error = %v, want ErrNotReady", err)
	}
}

func TestTLSAdmissionUsesTheVerifiedEpochCertificate(t *testing.T) {
	manager := newFakeManager(t)
	unverified := &tls.Certificate{}
	manager.tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return unverified, nil
	}
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := adapter.ServerTLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if certificate != manager.current.certificate {
		t.Fatal("TLS admission returned a certificate outside the verified epoch")
	}
	if certificate == unverified {
		t.Fatal("TLS admission delegated to the manager's independently changing certificate")
	}
}

func TestSnapshotDoesNotBlockOnAttestationRefresh(t *testing.T) {
	manager := newFakeManager(t)
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}
	manager.refreshStarted = make(chan struct{})
	manager.refreshRelease = make(chan struct{})
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- adapter.Refresh(context.Background())
	}()
	<-manager.refreshStarted

	snapshotDone := make(chan error, 1)
	go func() {
		_, err := adapter.Snapshot(context.Background())
		snapshotDone <- err
	}()
	select {
	case err := <-snapshotDone:
		if !errors.Is(err, platform.ErrNotReady) {
			t.Fatalf("Snapshot error during refresh = %v, want ErrNotReady", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Snapshot blocked on the attestation refresh operation")
	}

	close(manager.refreshRelease)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRefreshHonorsContext(t *testing.T) {
	manager := newFakeManager(t)
	adapter, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager))
	if err != nil {
		t.Fatal(err)
	}
	manager.refreshStarted = make(chan struct{})
	manager.refreshRelease = make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- adapter.Refresh(context.Background())
	}()
	<-manager.refreshStarted

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- adapter.Refresh(ctx)
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("concurrent Refresh error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Refresh ignored context cancellation")
	}

	close(manager.refreshRelease)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestNewAWSRejectsMismatchedSnapshotKey(t *testing.T) {
	manager := newFakeManager(t)
	manager.current.keyID[0] ^= 0xff
	if _, err := newAWS(context.Background(), Config{Role: "tokenhive_tee"}, testDependencies(manager)); err == nil {
		t.Fatal("newAWS accepted evidence whose key ID does not match the public key")
	}
}

type fakeManager struct {
	current    *fakeSnapshot
	next       *fakeSnapshot
	refreshErr error
	tlsConfig  *tls.Config

	refreshStarted chan struct{}
	refreshRelease chan struct{}
}

func newFakeManager(t *testing.T) *fakeManager {
	t.Helper()
	return &fakeManager{
		current: newFakeSnapshot(t, "verified-evidence"),
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &tls.Certificate{}, nil
			},
		},
	}
}

func newFakeSnapshot(t *testing.T, evidence string) *fakeSnapshot {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(publicKeyDER)
	return &fakeSnapshot{
		privateKey:   privateKey,
		publicKeyDER: publicKeyDER,
		keyID:        keyID,
		certificate:  &tls.Certificate{},
		appID:        "sha256:tokenhive-app",
		attType:      shared.AttestationTypeSEVSNP,
		evidence:     []byte(base64.StdEncoding.EncodeToString([]byte(evidence))),
	}
}

func (m *fakeManager) ServerTLSConfig() *tls.Config { return m.tlsConfig.Clone() }
func (m *fakeManager) Snapshot() ratlsSnapshot      { return m.current }
func (m *fakeManager) Refresh(context.Context) error {
	if m.refreshStarted != nil {
		close(m.refreshStarted)
	}
	if m.refreshRelease != nil {
		<-m.refreshRelease
	}
	if m.refreshErr != nil {
		return m.refreshErr
	}
	if m.next != nil {
		m.current = m.next
		m.next = nil
	}
	return nil
}

type fakeSnapshot struct {
	privateKey   *ecdsa.PrivateKey
	publicKeyDER []byte
	keyID        [32]byte
	certificate  *tls.Certificate
	appID        string
	attType      string
	evidence     []byte
}

func (s *fakeSnapshot) Certificate() *tls.Certificate { return s.certificate }
func (s *fakeSnapshot) PublicKeyDER() ([]byte, error) {
	return append([]byte(nil), s.publicKeyDER...), nil
}
func (s *fakeSnapshot) SPKIHash() [32]byte { return s.keyID }
func (s *fakeSnapshot) SignDigest(digest [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.privateKey, digest[:])
}
func (s *fakeSnapshot) Evidence() (string, string, []byte, error) {
	return s.appID, s.attType, append([]byte(nil), s.evidence...), nil
}

func testDependencies(manager ratlsManager) dependencies {
	return dependencies{
		isSEVSNP:        func() bool { return true },
		isAWS:           func() bool { return true },
		validateMode:    func() error { return nil },
		newRATLSManager: func(context.Context, string, *shared.Logger) (ratlsManager, error) { return manager, nil },
	}
}
