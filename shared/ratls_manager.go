//go:build !mobile

package shared

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"sync"
	"time"
)

// launcherSocketPath is where the Confidential Space launcher exposes its
// attestation API. Its presence is how we tell "running in an enclave" apart
// from "running locally for dev." Kept in sync with shared/gcp_attestation.go.
const launcherSocketPath = "/run/container_launcher/teeserver.sock"

// RATLSManager owns an ephemeral ECDSA P-256 keypair and a self-signed
// X.509 certificate that embeds a platform attestation report as an extension.
//
// The keypair rotates on every Refresh, and the certificate that binds it is
// rebuilt with it, so the SPKI hash — what the attestation covers, and what a
// receipt names as its KeyID — changes at each rotation rather than being
// stable for the manager's lifetime (see the mu field below). The cert and its
// embedded attestation must be rotated for as long as the process serves: a
// GCP attestation expires in ~5 minutes and an AWS NitroTPM chain in hours,
// after which new TLS handshakes verifying via `VerifyRATLSPeer` fail on the
// evidence itself. Callers pick the cadence — RunRATLSRefresh on the timer the
// platform needs (RATLSRefreshInterval, or the SEV-SNP cadence that tracks the
// NitroTPM leaf).
//
// All accessors are safe for concurrent use; Refresh atomically swaps the
// keypair, the SPKI hash and the cert as one unit, without disrupting in-flight
// handshakes (Go's TLS stack reads GetCertificate per-handshake, so existing
// sessions are unaffected), and a snapshot taken before a rotation keeps
// signing with the key its own evidence attests.
type RATLSManager struct {
	role        string
	extraNonces []string
	// mu guards priv/spkiHash/cert as one unit. The keypair rotates on every
	// Refresh (forward secrecy), so a reader must never see a cert from one
	// epoch with the priv/SPKI of another — all three are swapped together.
	mu       sync.RWMutex
	priv     *ecdsa.PrivateKey
	spkiHash [32]byte
	cert     *tls.Certificate
}

// NewRATLSManager generates a fresh keypair and builds the initial cert.
// Returns an error if the launcher socket exists (i.e. we're in an enclave)
// and the attestation request fails — a launcher failure in enclave mode
// is a real production issue and we must not silently mask it as
// standalone-dev mode.
func NewRATLSManager(ctx context.Context, role string, extraNonces []string) (*RATLSManager, error) {
	m := &RATLSManager{
		role:        role,
		extraNonces: extraNonces,
	}
	// Refresh generates the first keypair + cert and publishes them.
	if err := m.Refresh(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Refresh generates a FRESH keypair, requests an attestation binding it,
// builds a new cert, and atomically swaps {priv, spkiHash, cert} in. Rotating
// the keypair on every refresh bounds the blast radius of a key extraction to
// one refresh interval. Existing TLS sessions keep whatever cert was active at
// handshake time (Go reads GetCertificate per-handshake); new handshakes pick
// up the new cert+key.
//
// In standalone (non-enclave) mode — detected by the absence of the
// Confidential Space launcher socket — Refresh produces a cert without
// the attestation extension. Peers verifying via VerifyRATLSPeer will
// reject such certs; standalone-mode TEE↔TEE comms must use a different
// TLS verifier path.
func (m *RATLSManager) Refresh(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ratls refresh: generate ecdsa key: %w", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("ratls refresh: marshal SPKI: %w", err)
	}
	spkiHash := sha256.Sum256(spkiDER)

	// Build everything off local vars so the slow attestation call binds the
	// NEW key without exposing a half-rotated state to readers.
	extraExts, err := m.acquireAttestationExts(ctx, priv, spkiHash)
	if err != nil {
		return fmt.Errorf("ratls refresh: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("ratls refresh: random serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: m.role},
		// Cert time bounds are a formality for a self-signed attested leaf:
		// RA-TLS verification checks the *evidence* inside the certificate, not
		// this window. They are set long anyway, because a consumer that does
		// strict chain checks (the Hub's certificate pin, a standard TLS client
		// validating a pinned leaf) is bounded by them alone — and a
		// day-long window turns every such deployment that is not running a
		// refresher into one that stops authenticating a day after it boots,
		// which says nothing useful about the evidence. Freshness is the
		// evidence's job (hours, on AWS) and the refresh cadence's
		// (RATLSRefreshIntervalSNP, or RATLSRefreshInterval on Confidential
		// Space), never this window's.
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extraExts,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("ratls refresh: create cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(derCert)
	if err != nil {
		return fmt.Errorf("ratls refresh: parse just-created cert: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derCert},
		PrivateKey:  priv,
		Leaf:        leaf,
	}

	m.mu.Lock()
	m.priv = priv
	m.spkiHash = spkiHash
	m.cert = cert
	m.mu.Unlock()
	return nil
}

// Certificate returns the currently-active certificate. Mostly used by tests
// and admin endpoints; live TLS configs should use GetCertificate so they
// automatically pick up Refresh()es.
func (m *RATLSManager) Certificate() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

// CertificateRaw returns the DER-encoded leaf of the currently-active cert.
// API-compatible with the LegoManager.GetCertificateRaw() shape it replaces.
func (m *RATLSManager) CertificateRaw() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil
	}
	return m.cert.Certificate[0]
}

// SPKIHash returns sha256(SPKI) of the current TLS keypair. The keypair rotates
// on every Refresh, so callers must re-read this after a rotation.
func (m *RATLSManager) SPKIHash() [32]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.spkiHash
}

// PublicKeyDER returns the PKIX-marshaled RA-TLS public key. Its sha256 is
// what the attestation's SPKI nonce commits to, so a verifier can recover
// and trust the registration-signing key from the attestation alone.
func (m *RATLSManager) PublicKeyDER() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return x509.MarshalPKIXPublicKey(&m.priv.PublicKey)
}

// SignRegistration signs a registration digest with the RA-TLS private key
// (ECDSA P-256, ASN.1 form). The key never leaves the enclave.
func (m *RATLSManager) SignRegistration(digest [32]byte) ([]byte, error) {
	m.mu.RLock()
	priv := m.priv
	m.mu.RUnlock()
	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}

// RATLSSnapshot is an immutable point-in-time view of one RA-TLS epoch
// {priv, spkiHash, cert}. Because the keypair rotates on every Refresh, code
// that needs several of these values to come from the SAME epoch (e.g.
// building a registration body: attestation + SPKI + body signature) must take
// one Snapshot and read everything from it, rather than making separate
// manager calls that could straddle a rotation.
type RATLSSnapshot struct {
	priv     *ecdsa.PrivateKey
	spkiHash [32]byte
	cert     *tls.Certificate
}

// Snapshot captures the current {priv, spkiHash, cert} under a single lock.
func (m *RATLSManager) Snapshot() RATLSSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return RATLSSnapshot{priv: m.priv, spkiHash: m.spkiHash, cert: m.cert}
}

// Certificate returns the snapshot's cert.
func (s RATLSSnapshot) Certificate() *tls.Certificate { return s.cert }

// SPKIHash returns sha256(SPKI) of the snapshot's keypair.
func (s RATLSSnapshot) SPKIHash() [32]byte { return s.spkiHash }

// PublicKeyDER returns the PKIX-marshaled public key of the snapshot's keypair.
func (s RATLSSnapshot) PublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
}

// SignRegistration signs a registration digest with the snapshot's private key.
func (s RATLSSnapshot) SignRegistration(digest [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
}

// GetCertificate is intended for tls.Config.GetCertificate. Always returns
// the current cert, so handshakes that arrive after a Refresh() see the
// fresh attestation.
func (m *RATLSManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	c := m.cert
	m.mu.RUnlock()
	if c == nil {
		return nil, errors.New("ratls: no cert available (Refresh never succeeded)")
	}
	return c, nil
}

// GetClientCertificate is intended for tls.Config.GetClientCertificate when
// the TEE acts as TLS client and the peer requires client certs (mTLS).
func (m *RATLSManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.GetCertificate(nil)
}

// ServerTLSConfig returns a base tls.Config suitable for a TEE acting as a
// TLS server. It installs GetCertificate so refreshes are picked up, but
// does NOT set ClientAuth or VerifyPeerCertificate — callers wiring up
// mTLS for TEE↔TEE links must add those themselves with a verifier built
// from `VerifyRATLSPeer`.
func (m *RATLSManager) ServerTLSConfig() *tls.Config {
	// TLS 1.3 only on the RA-TLS layer (TEE↔TEE peer link, client↔TEE).
	// This is independent of the protocol's separate TLS-to-target
	// handshake handled by minitls, which must keep 1.2 support.
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
	}
}

// IsEnclaveMode reports whether the process appears to be running inside a
// GCP Confidential Space launcher (the attestation socket is present).
// Useful for callers that need to take different code paths in dev vs prod
// — but production code paths should be the default; reach for this only
// when local-dev parity is genuinely required.
func IsEnclaveMode() bool {
	_, err := os.Stat(launcherSocketPath)
	return err == nil
}

// IsProductionTEE reports whether this TEE runs in a real attested environment
// — Confidential Space (launcher socket) or SEV-SNP (/dev/sev-guest) — versus
// local dev. Both take the RA-TLS + attested-registration path.
func IsProductionTEE() bool {
	return IsEnclaveMode() || IsSEVSNPMode()
}

// acquireAttestationExts builds the attestation cert extension(s) for the
// current platform, dispatching on how this TEE is deployed:
//
//   - Confidential Space (launcher socket present): emit a CS-JWT under
//     AttestationOID. This is the deployed v2 path and takes priority.
//   - Plain SEV-SNP CVM (/dev/sev-guest present): emit a marshaled SEV-SNP
//     report under AttestationOIDSEVSNP, with report_data binding the SPKI
//     hash and the self binary hash. Secure Boot images also emit a small
//     AttestationOIDSecureBoot marker that makes updated verifiers apply R.
//   - Standalone dev (neither present): no extension. Peers using
//     VerifyRATLSPeer will reject such certs; standalone TEE↔TEE comms must
//     use a different verifier path.
//
// A launcher-socket-present call that fails is a real production bug and is
// surfaced as an error rather than silently degrading to standalone mode.
func (m *RATLSManager) acquireAttestationExts(ctx context.Context, priv *ecdsa.PrivateKey, spkiHash [32]byte) ([]pkix.Extension, error) {
	if _, err := os.Stat(launcherSocketPath); !errors.Is(err, fs.ErrNotExist) {
		spkiNonce := SPKINoncePrefix(m.role) + hex.EncodeToString(spkiHash[:])
		nonces := append([]string{spkiNonce}, m.extraNonces...)
		jwt, err := GenerateGCPAttestation(ctx, nonces...)
		if err != nil {
			return nil, err
		}
		return []pkix.Extension{{Id: AttestationOID, Critical: false, Value: jwt}}, nil
	}

	if IsSEVSNPMode() {
		// Combined attestation: AMD SEV-SNP report + vTPM AK/PCR quotes, with the
		// SEV report_data committing to the vTPM AK and this cert's SPKI. Code
		// identity lives in PCR 8 (app) and the measured boot PCRs. The SEV
		// measurement is firmware-only, so the binding to the AK is what makes the
		// PCR quote trustworthy without splicing. Secure Boot certificates retain a
		// legacy extension for old clients and add a separate extension for updated
		// clients to verify the event log and release key R during the TLS handshake.
		spkiDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("ra-tls SPKI: %w", err)
		}
		// appHash (= sha256(app bundle)) is measured + exported by the loader; it's
		// the cross-cloud payload identity, proven against PCR 8 by the verifier.
		appHash, herr := hex.DecodeString(os.Getenv("SNP_APP_HASH"))
		if herr != nil || len(appHash) == 0 {
			return nil, fmt.Errorf("SNP_APP_HASH not set by loader")
		}
		var att []byte
		tag := byte(snpAttestTagGCP)
		if IsAWSSEVSNP() {
			tag = snpAttestTagAWS
			att, err = GenerateCombinedAWSAttestation(spkiDER, appHash)
		} else {
			att, err = GenerateCombinedGCPAttestation(spkiDER, appHash)
		}
		if err != nil {
			return nil, err
		}
		return snpRATLSExtensions(tag, att, secureBootAttestationEnabled()), nil
	}

	return nil, nil
}

func snpRATLSExtensions(legacyTag byte, att []byte, secureBoot bool) []pkix.Extension {
	// Keep the legacy extension byte-for-byte compatible with old clients.
	legacy := pkix.Extension{
		Id:       AttestationOIDSEVSNP,
		Critical: false,
		Value:    append([]byte{legacyTag}, att...),
	}
	if !secureBoot {
		return []pkix.Extension{legacy}
	}

	secure := pkix.Extension{
		Id:       AttestationOIDSecureBoot,
		Critical: false,
		Value:    []byte{secureBootRATLSExtensionVersion},
	}
	return []pkix.Extension{legacy, secure}
}
