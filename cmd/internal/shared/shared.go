// Package shared holds the small, reusable pieces the simulation binaries
// (mockprovider, tee, faketee, hub, verify, agent) share: the .sim working
// directory, the provider-credential fixtures, the provider-signed policy the
// TEE loads, and a throwaway test CA.
//
// Nothing here is production code. It exists so the simulation runs end to end
// on a laptop with zero external dependencies and zero real credentials, while
// still exercising the real tee.Service — the simulation never re-implements
// the TEE. The /v1/execute wire format is not here for that reason: it lives
// with tee.ServeExecute so that simulation and production speak one definition.
package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// Default fixtures. The provider's own key signs the policy; the TEE only ever
// verifies it.
const (
	providerName = "openai-sim"
	providerHost = "127.0.0.1:18080"
	providerPath = "/v1/chat/completions"
)

// ConfigDir returns the simulation working directory. Override with
// TOKENHIVE_SIM_DIR to keep runs isolated.
func ConfigDir() string {
	if d := os.Getenv("TOKENHIVE_SIM_DIR"); d != "" {
		return d
	}
	return ".sim"
}

// Providers maps a provider name to the credential (API token) the TEE must
// keep secret. The Hub never sees these values.
type Providers map[string]string

// EnsureDefaults writes the fixture files if they are missing: the provider
// credential, the provider's signing key, and a provider-signed policy the TEE
// loads. The key is generated once and persisted, because the policy is signed
// by it and a regenerated key would invalidate the policy already on disk.
func EnsureDefaults() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "providers.json"), Providers{
		providerName: "sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}); err != nil {
		return err
	}
	key, err := loadOrGenProviderKey()
	if err != nil {
		return err
	}
	// The policy is derived from the stable key, so it is safe to (re)write it
	// whenever defaults are ensured.
	signed, err := policy.SignPolicy(defaultPolicy(), key)
	if err != nil {
		return fmt.Errorf("sign default policy: %w", err)
	}
	enc, err := signed.EncodeCanonical()
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	if err := os.WriteFile(policyPath(), enc, 0o644); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

func providerKeyPath() string { return filepath.Join(ConfigDir(), "provider_key.pem") }
func policyPath() string      { return filepath.Join(ConfigDir(), "policy.cbor") }

func loadOrGenProviderKey() (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(providerKeyPath()); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(providerKeyPath(),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// defaultPolicy is the whitelist the simulated TEE enforces. It is the real
// policy.Policy type — the simulation loads it through the genuine
// policy.Set, not a parallel hand-rolled structure.
func defaultPolicy() policy.Policy {
	now := time.Now()
	return policy.Policy{
		Version:  policy.VersionV1,
		Provider: providerName,
		Hosts:    []string{providerHost},
		Rules: []policy.Rule{
			{Methods: []string{"POST"}, Path: providerPath, AllowStream: true, QueryKeys: []string{"fault"}},
		},
		Credential: policy.Credential{Header: "Authorization", Scheme: "Bearer"},
		Limits: policy.Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 20,
			AllowedHeaders:   []string{"Content-Type"},
		},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),

		// The provider's price, in the provider's own policy. The Hub reads it
		// from here rather than carrying a table of its own: pricing authority
		// is the provider's, and a policy hash on the receipt is what makes
		// the charge reproducible.
		//
		// Per-request and per-model only. Volume pricing is covered by the hub
		// package's unit tests and left at zero here so the harness's per-run
		// totals stay readable.
		RateCard: policy.RateCard{
			PerRequestMicros: 1_000_000, // 1.00 unit per completed request
			ModelPremiumMicros: map[string]uint64{
				"sim-mock-large": 500_000, // 0.50 unit surcharge for the big model
			},
		},
	}
}

// LoadPolicySet reads the provider-signed policy and installs it into a
// policy.Set, verifying the signature exactly as the real TEE would.
func LoadPolicySet() (*policy.Set, error) {
	b, err := os.ReadFile(policyPath())
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	signed, err := policy.DecodeSignedPolicy(b)
	if err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	set := policy.NewSet()
	if err := set.Add(signed, time.Now()); err != nil {
		return nil, fmt.Errorf("install policy: %w", err)
	}
	return set, nil
}

// LoadProviders reads the provider-credential fixture.
func LoadProviders() (Providers, error) {
	var p Providers
	if err := readJSON(filepath.Join(ConfigDir(), "providers.json"), &p); err != nil {
		return nil, err
	}
	return p, nil
}

// WriteTEEIdentity persists the public identity of a sim epoch so the verifier
// (hub/verify) can resolve EvidenceHash without an inline attestation — exactly
// the "attestation cache" role a production verifier would fill from its own
// trust store.
func WriteTEEIdentity(id platform.Identity) error {
	return writeJSON(filepath.Join(ConfigDir(), "tee_identity.json"), id)
}

// LoadTEEIdentity reads the persisted public identity.
func LoadTEEIdentity() (platform.Identity, error) {
	var id platform.Identity
	if err := readJSON(filepath.Join(ConfigDir(), "tee_identity.json"), &id); err != nil {
		return platform.Identity{}, err
	}
	return id, nil
}

// CAPEMPath is where mockprovider drops its CA certificate for the TEE to trust.
func CAPEMPath() string { return filepath.Join(ConfigDir(), "ca.pem") }

// GenCerts generates a throwaway CA and a server certificate for the loopback
// interface, returning a TLS config for the mock provider and the CA PEM for
// the TEE to trust. No external tooling required.
func GenCerts() (*tls.Config, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tokenhive-sim-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	srvCert, err := tls.X509KeyPair(pemEncode("CERTIFICATE", srvDER), pemEncode("EC PRIVATE KEY",
		mustMarshalEC(srvKey)))
	if err != nil {
		return nil, nil, err
	}

	caPEM := pemEncode("CERTIFICATE", caDER)
	return &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12}, caPEM, nil
}

// LoadCAPool reads the CA certificate mockprovider wrote, for the TEE's TLS
// trust roots.
func LoadCAPool() (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(CAPEMPath())
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w (did mockprovider start with TLS?)", CAPEMPath(), err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates parsed from %s", CAPEMPath())
	}
	return pool, nil
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func mustMarshalEC(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

func writeIfAbsent(path string, v any) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return writeJSON(path, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return json.Unmarshal(b, v)
}
