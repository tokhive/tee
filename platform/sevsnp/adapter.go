//go:build !mobile

// Package sevsnp adapts Reclaim's RA-TLS and combined AWS SEV-SNP evidence for
// the platform-neutral TokenHive trusted runtime.
package sevsnp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Config controls the identity emitted by the AWS SEV-SNP adapter.
type Config struct {
	Role   string
	Logger *shared.Logger
}

// Adapter keeps admission, evidence, and signing on a verified RA-TLS epoch.
type Adapter struct {
	manager ratlsManager
	baseTLS *tls.Config

	refreshGate chan struct{}
	mu          sync.RWMutex
	current     *epoch
	healthy     bool
}

// NewAWS initializes and self-verifies an AWS SEV-SNP RA-TLS epoch. It refuses
// to fall back to local development or another cloud platform.
func NewAWS(ctx context.Context, config Config) (*Adapter, error) {
	deps := dependencies{
		isSEVSNP:     shared.IsSEVSNPMode,
		isAWS:        shared.IsAWSSEVSNP,
		validateMode: shared.ValidateSNPAttestationType,
		newRATLSManager: func(ctx context.Context, role string, logger *shared.Logger) (ratlsManager, error) {
			manager, err := shared.NewRATLSManager(ctx, role, nil)
			if err != nil {
				return nil, err
			}
			return &sharedManager{manager: manager, logger: logger}, nil
		},
	}
	return newAWS(ctx, config, deps)
}

type dependencies struct {
	isSEVSNP        func() bool
	isAWS           func() bool
	validateMode    func() error
	newRATLSManager func(context.Context, string, *shared.Logger) (ratlsManager, error)
}

func newAWS(ctx context.Context, config Config, deps dependencies) (*Adapter, error) {
	config.Role = strings.TrimSpace(config.Role)
	if config.Role == "" || len(config.Role) > 64 {
		return nil, fmt.Errorf("SEV-SNP role must contain between 1 and 64 bytes")
	}
	if err := deps.validateMode(); err != nil {
		return nil, fmt.Errorf("validate SEV-SNP attestation mode: %w", err)
	}
	if !deps.isSEVSNP() {
		return nil, errors.New("AWS SEV-SNP adapter requires /dev/sev-guest")
	}
	if !deps.isAWS() {
		return nil, errors.New("AWS SEV-SNP adapter requires an Amazon EC2 guest")
	}
	if config.Logger == nil {
		config.Logger = shared.NewNopLogger()
	}

	manager, err := deps.newRATLSManager(ctx, config.Role, config.Logger)
	if err != nil {
		return nil, fmt.Errorf("initialize RA-TLS manager: %w", err)
	}
	baseTLS := manager.ServerTLSConfig()
	if baseTLS == nil {
		return nil, errors.New("RA-TLS manager did not provide a server TLS configuration")
	}

	adapter := &Adapter{
		manager:     manager,
		baseTLS:     baseTLS.Clone(),
		refreshGate: make(chan struct{}, 1),
	}
	initial, err := buildEpoch(manager.Snapshot())
	if err != nil {
		return nil, fmt.Errorf("verify initial AWS SEV-SNP epoch: %w", err)
	}
	adapter.current = initial
	adapter.healthy = true
	return adapter, nil
}

// Healthy reports whether new trusted work and TLS handshakes may be admitted.
func (a *Adapter) Healthy() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// ServerTLSConfig returns an RA-TLS server configuration whose certificate
// admission fails closed while evidence refresh is unhealthy.
func (a *Adapter) ServerTLSConfig() *tls.Config {
	config := a.baseTLS.Clone()
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if !a.healthy || a.current == nil {
			return nil, platform.ErrNotReady
		}
		certificate := a.current.snapshot.Certificate()
		if certificate == nil {
			return nil, platform.ErrNotReady
		}
		return certificate, nil
	}
	return config
}

// Snapshot returns the last fully verified immutable epoch.
func (a *Adapter) Snapshot(ctx context.Context) (platform.Epoch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !a.healthy || a.current == nil {
		return nil, platform.ErrNotReady
	}
	return a.current, nil
}

// Refresh rotates the RA-TLS key and evidence. New handshakes are rejected
// from the start of rotation until the new epoch has self-verified.
func (a *Adapter) Refresh(ctx context.Context) error {
	select {
	case a.refreshGate <- struct{}{}:
		defer func() { <-a.refreshGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	a.healthy = false
	a.mu.Unlock()
	if err := a.manager.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh AWS SEV-SNP RA-TLS epoch: %w", err)
	}
	next, err := buildEpoch(a.manager.Snapshot())
	if err != nil {
		return fmt.Errorf("verify refreshed AWS SEV-SNP epoch: %w", err)
	}
	a.mu.Lock()
	a.current = next
	a.healthy = true
	a.mu.Unlock()
	return nil
}

type epoch struct {
	identity platform.Identity
	snapshot ratlsSnapshot
}

func buildEpoch(snapshot ratlsSnapshot) (*epoch, error) {
	if snapshot == nil || snapshot.Certificate() == nil {
		return nil, errors.New("RA-TLS snapshot has no certificate")
	}
	publicKeyDER, err := snapshot.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("read RA-TLS public key: %w", err)
	}
	computedKeyID := sha256.Sum256(publicKeyDER)
	keyID := snapshot.SPKIHash()
	if computedKeyID != keyID {
		return nil, errors.New("RA-TLS snapshot public key does not match SPKI hash")
	}
	applicationID, attestationType, encodedEvidence, err := snapshot.Evidence()
	if err != nil {
		return nil, fmt.Errorf("extract verified evidence: %w", err)
	}
	if applicationID == "" {
		return nil, errors.New("verified evidence has no application identity")
	}
	if attestationType != shared.AttestationTypeSEVSNP && attestationType != shared.AttestationTypeSecureBoot {
		return nil, fmt.Errorf("unexpected attestation type %q", attestationType)
	}
	evidence, err := base64.StdEncoding.DecodeString(string(encodedEvidence))
	if err != nil {
		return nil, fmt.Errorf("decode verified SEV-SNP evidence: %w", err)
	}
	if len(evidence) == 0 {
		return nil, errors.New("verified SEV-SNP evidence is empty")
	}

	identity := platform.Identity{
		Platform:        platform.PlatformAWSSEVSNP,
		AttestationType: attestationType,
		ApplicationID:   applicationID,
		Evidence:        evidence,
		EvidenceHash:    sha256.Sum256(evidence),
		PublicKeyDER:    append([]byte(nil), publicKeyDER...),
		KeyID:           keyID,
	}
	return &epoch{identity: identity, snapshot: snapshot}, nil
}

func (e *epoch) Identity() platform.Identity {
	return platform.CloneIdentity(e.identity)
}

func (e *epoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := e.snapshot.SignDigest(digest)
	if err != nil {
		return platform.Signature{}, fmt.Errorf("sign with attested epoch key: %w", err)
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.identity.KeyID,
		Value:     value,
	}, nil
}

type ratlsManager interface {
	ServerTLSConfig() *tls.Config
	Snapshot() ratlsSnapshot
	Refresh(context.Context) error
}

type ratlsSnapshot interface {
	Certificate() *tls.Certificate
	PublicKeyDER() ([]byte, error)
	SPKIHash() [32]byte
	SignDigest([32]byte) ([]byte, error)
	Evidence() (applicationID, attestationType string, encodedEvidence []byte, err error)
}

type sharedManager struct {
	manager *shared.RATLSManager
	logger  *shared.Logger
}

func (m *sharedManager) ServerTLSConfig() *tls.Config      { return m.manager.ServerTLSConfig() }
func (m *sharedManager) Refresh(ctx context.Context) error { return m.manager.Refresh(ctx) }
func (m *sharedManager) Snapshot() ratlsSnapshot {
	return &sharedSnapshot{snapshot: m.manager.Snapshot(), logger: m.logger}
}

type sharedSnapshot struct {
	snapshot shared.RATLSSnapshot
	logger   *shared.Logger
}

func (s *sharedSnapshot) Certificate() *tls.Certificate { return s.snapshot.Certificate() }
func (s *sharedSnapshot) PublicKeyDER() ([]byte, error) { return s.snapshot.PublicKeyDER() }
func (s *sharedSnapshot) SPKIHash() [32]byte            { return s.snapshot.SPKIHash() }
func (s *sharedSnapshot) SignDigest(digest [32]byte) ([]byte, error) {
	return s.snapshot.SignRegistration(digest)
}
func (s *sharedSnapshot) Evidence() (string, string, []byte, error) {
	return shared.ExtractIdentityFromRATLS(s.snapshot, s.logger)
}

var _ platform.Adapter = (*Adapter)(nil)
var _ platform.Epoch = (*epoch)(nil)
