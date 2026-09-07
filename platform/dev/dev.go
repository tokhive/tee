// Package dev mints the software epoch the cloud adapter skeletons use in
// their AllowUntrusted (wiring-only) mode.
//
// It exists so the alicloud and tencent adapters can be exercised end to end —
// listener up, jobs flowing, receipts signed — on a real cloud instance before
// their attestation verification is implemented. The identity it produces
// carries the CLOUD's platform string (never "simulated"), so a receipt from it
// is refused by the cloud's own verifier by design: this epoch is explicitly
// UNATTESTED, and nothing downstream may mistake it for trusted hardware.
package dev

import (
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
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// AttestationType labels the (fake) dev attestation format.
const AttestationType = "dev-unattested"

// DevEvidence is the self-described evidence blob a dev epoch carries. The
// Attested field is always false; a verifier must reject it.
type DevEvidence struct {
	Version    int    `json:"version"`
	Attested   bool   `json:"attested"`
	Platform   string `json:"platform"`
	HostData   string `json:"host_data"`
	Measurement string `json:"measurement"`
}

// epoch is the software implementation of platform.Epoch for the dev path.
type epoch struct {
	platform string
	priv     *ecdsa.PrivateKey
	pubDER   []byte
	keyID    [32]byte
	evidence []byte

	serverTLSOnce sync.Once
	serverTLS     *tls.Config
}

// NewEpoch generates a fresh software signing key for a dev epoch carrying the
// given platform string. Callers must use their own cloud platform string so
// receipts are refused by the cloud verifier, never mistaken for "simulated".
func NewEpoch(platformName, applicationID string) (platform.Epoch, error) {
	if platformName == "" || applicationID == "" {
		return nil, errors.New("dev epoch needs a platform name and application id")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal dev public key: %w", err)
	}
	keyID := sha256.Sum256(pubDER)
	ev := DevEvidence{
		Version:     1,
		Attested:    false,
		Platform:    platformName,
		HostData:    "tokenhive-dev-wiring-only",
		Measurement: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	evidence, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal dev evidence: %w", err)
	}
	return &epoch{
		platform: platformName,
		priv:     priv,
		pubDER:   pubDER,
		keyID:    keyID,
		evidence: evidence,
	}, nil
}

// Identity returns the public identity of this epoch. Platform is the cloud
// platform string the caller chose, AttestationType is dev-unattested.
func (e *epoch) Identity() platform.Identity {
	return platform.Identity{
		Platform:        e.platform,
		AttestationType: AttestationType,
		ApplicationID:   "tokenhive-dev@" + e.platform,
		Evidence:        append([]byte(nil), e.evidence...),
		EvidenceHash:    sha256.Sum256(e.evidence),
		PublicKeyDER:    append([]byte(nil), e.pubDER...),
		KeyID:           e.keyID,
	}
}

// Sign produces the same ECDSA-P256-SHA256-ASN1 shape a real attested key
// would. The signature proves nothing about hardware — see the package comment.
func (e *epoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, e.priv, digest[:])
	if err != nil {
		return platform.Signature{}, fmt.Errorf("dev sign: %w", err)
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.keyID,
		Value:     value,
	}, nil
}

// ServerTLSConfig mints a self-signed leaf from the dev key so the -mtls
// wiring can be exercised. Like the identity, the certificate is unattested:
// a Hub pinning it gets exactly the dev key, nothing more.
func (e *epoch) ServerTLSConfig() *tls.Config {
	e.serverTLSOnce.Do(func() { e.serverTLS = e.mintServerTLS() })
	return e.serverTLS.Clone()
}

func (e *epoch) mintServerTLS() *tls.Config {
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(e.keyID[:8]),
		Subject:      pkix.Name{CommonName: "tokenhive-dev-tee"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &e.priv.PublicKey, e.priv)
	if err != nil {
		return &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, fmt.Errorf("mint dev certificate: %w", err)
			},
		}
	}
	certDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalEC(e.priv)})
	cert, err := tls.X509KeyPair(certDER, keyDER)
	if err != nil {
		return &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, fmt.Errorf("load minted dev certificate: %w", err)
			},
		}
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func mustMarshalEC(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

var _ platform.Epoch = (*epoch)(nil)
