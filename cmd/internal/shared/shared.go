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

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// Default fixtures. The provider's own key signs the policy; the TEE only ever
// verifies it.
const (
	providerName  = "openai-sim"
	providerCheap = "cheap-sim"
	providerHost  = "127.0.0.1:18080"
	providerPath  = "/v1/chat/completions"
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
// credentials, the providers' signing keys, a provider-signed whitelist policy
// per provider that the TEE loads, and the Hub's seller-reported rate table.
// Each key is generated once and persisted, because the policy is signed by it
// and a regenerated key would invalidate the policy already on disk.
func EnsureDefaults() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "providers.json"), Providers{
		providerName:  "sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		providerCheap: "sk-sim-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
	}); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "rates.json"), DefaultRates()); err != nil {
		return err
	}
	key, err := loadOrGenProviderKey()
	if err != nil {
		return err
	}
	// primary provider
	if err := writePolicy(providerName, providerPolicy(providerName), key); err != nil {
		return err
	}
	// a second, cheaper provider so the harness can exercise lowest-price
	// scheduling over two signed policies pointing at the same upstream.
	if err := writePolicy(providerCheap, providerPolicy(providerCheap), key); err != nil {
		return err
	}
	return nil
}

// DefaultRates is the Hub's seller-reported market price list for the
// simulation. Prices are commercial data kept by the Hub — deliberately
// outside the Provider Policy, which is a whitelist, not a price sheet.
func DefaultRates() Rates {
	return Rates{
		// 1.00 unit per request; premium model carries a surcharge.
		providerName: hub.RateCard{PerRequestMicros: 1_000_000, ModelPremiumMicros: map[string]uint64{
			"sim-mock-large": 500_000, // 0.50 unit surcharge
		}},
		// 0.30 unit per request — the one the scheduler wants.
		providerCheap: hub.RateCard{PerRequestMicros: 300_000},
	}
}

// Rates is the Hub's market table: provider name to seller price card.
type Rates map[string]hub.RateCard

// LoadRates reads the Hub's rate table.
func LoadRates() (Rates, error) {
	var rates Rates
	if err := readJSON(filepath.Join(ConfigDir(), "rates.json"), &rates); err != nil {
		return nil, err
	}
	return rates, nil
}

// writePolicy encodes and writes a provider policy to its per-provider path.
func writePolicy(provider string, p policy.Policy, key *ecdsa.PrivateKey) error {
	signed, err := policy.SignPolicy(p, key)
	if err != nil {
		return fmt.Errorf("sign policy: %w", err)
	}
	enc, err := signed.EncodeCanonical()
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	path := policyPathFor(provider)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("make policy dir: %w", err)
	}
	if err := os.WriteFile(path, enc, 0o644); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

func providerKeyPath() string { return filepath.Join(ConfigDir(), "provider_key.pem") }
func policyPath() string      { return filepath.Join(ConfigDir(), "policy.cbor") }
func policyPathFor(p string) string {
	if p == providerName {
		return policyPath()
	}
	return filepath.Join(ConfigDir(), "policies", p+".cbor")
}

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

// providerPolicy is the whitelist the simulated TEE enforces for one provider.
// It is the real policy.Policy type — the simulation loads it through the
// genuine policy.Set, not a parallel hand-rolled structure. The two providers
// differ only in price, so the Hub's lowest-price scheduler has something to
// choose between; both point at the same upstream host.
//
// The whitelisted paths mirror the Hub's user-facing routes: the OpenAI chat
// completions endpoint, the OpenAI Responses endpoint, the Anthropic messages
// endpoint, and the streaming-session endpoint. In a real deployment these
// paths would live on different hosts per provider (api.openai.com vs
// api.anthropic.com); the simulation runs all shapes behind one mock host so
// a single signed policy per provider covers all four routes.
func providerPolicy(provider string) policy.Policy {
	now := time.Now()
	hosts := []string{providerHost}
	rules := []policy.Rule{
		{Methods: []string{"POST"}, Path: providerPath, AllowStream: true, QueryKeys: []string{"fault"}},
		// The OpenAI Responses API: a streaming endpoint served by the same
		// mock host, whitelisted so /v1/responses user requests can dispatch
		// to these providers.
		{Methods: []string{"POST"}, Path: "/v1/responses", AllowStream: true, QueryKeys: []string{"fault"}},
		// The Anthropic Messages API: same pattern, so /v1/messages user
		// requests (model: claude-*) can dispatch to these providers.
		{Methods: []string{"POST"}, Path: "/v1/messages", AllowStream: true, QueryKeys: []string{"fault"}},
		// The streaming-session endpoint: a WebSocket upgrade, so it is a GET
		// with no body whose whole framing is the Hub's business. AllowStream is
		// set because the tunnel is unbounded by definition.
		{Methods: []string{"GET"}, Path: "/v1/realtime", AllowStream: true, AllowAnyQuery: true},
	}
	credential := policy.Credential{Header: "Authorization", Scheme: "Bearer"}
	limits := policy.Limits{
		MaxResponseBytes: 1 << 20,
		MaxBodyBytes:     1 << 20,
		AllowedHeaders:   []string{"Content-Type"},
	}

	return policy.Policy{
		Version:    policy.VersionV1,
		Provider:   provider,
		Hosts:      hosts,
		Rules:      rules,
		Credential: credential,
		Limits:     limits,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(365 * 24 * time.Hour).Unix(),
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

// LoadPolicySetAll loads every installed provider policy: the legacy single
// policy.cbor (the primary provider) plus any per-provider file under
// policies/. The Hub and the real TEE use this so that multi-provider scenarios
// (lowest-price scheduling) see the whole supply; summaries that keep using
// LoadPolicySet are unaffected because the primary provider's policy is always
// included first.
func LoadPolicySetAll() (*policy.Set, error) {
	set := policy.NewSet()
	now := time.Now()

	paths := []string{policyPath()}
	extra, err := filepath.Glob(filepath.Join(ConfigDir(), "policies", "*.cbor"))
	if err != nil {
		return nil, fmt.Errorf("list policies dir: %w", err)
	}
	paths = append(paths, extra...)

	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", path, err)
		}
		signed, err := policy.DecodeSignedPolicy(b)
		if err != nil {
			return nil, fmt.Errorf("decode policy %s: %w", path, err)
		}
		if err := set.Add(signed, now); err != nil {
			return nil, fmt.Errorf("install policy %s: %w", path, err)
		}
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
