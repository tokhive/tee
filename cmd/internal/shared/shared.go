// Package shared holds the small, reusable pieces the simulation binaries
// (mockprovider, tee, faketee, hub, verify, agent) share: the .sim working
// directory, the Hub-predefined whitelist policy the TEE loads, the Hub's
// seller rate table, a throwaway test CA, and the one-shot credential
// registration the simulation-only CLI tools (hub -n, streamer) use when they
// talk to a TEE directly instead of through a resident Hub with dialing agents.
//
// Nothing here is production code. It exists so the simulation runs end to end
// on a laptop with zero external dependencies and zero real credentials, while
// still exercising the real tee.Service — the simulation never re-implements
// the TEE. The /v1/execute wire format is not here for that reason: it lives
// with tee.ServeExecute so that simulation and production speak one definition.
package shared

import (
	"context"
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
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// Default fixtures.
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

// EnsureDefaults writes the fixture files if they are missing: a
// Hub-predefined whitelist policy per provider (deployment config) and the
// Hub's seller-reported rate table. Credentials are intentionally NOT written:
// they arrive at runtime through agent registration (see the package comment).
func EnsureDefaults() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "rates.json"), DefaultRates()); err != nil {
		return err
	}
	// primary provider
	if err := writePolicy(providerName, providerPolicy(providerName)); err != nil {
		return err
	}
	// a second, cheaper provider so the harness can exercise lowest-price
	// scheduling over two policies pointing at the same upstream.
	if err := writePolicy(providerCheap, providerPolicy(providerCheap)); err != nil {
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

// SealCredential fetches a TEE's inbox public key and seals a provider's token
// to it, returning the envelope a caller can carry into a job's spec.Credential.
// It is the sender half of agent registration for a caller that talks to a TEE
// directly (no dialing agent): the token travels sealed, and only the TEE
// holding the matching private key can open it. The TEE itself stores nothing —
// the sealed token lives wherever the caller puts it, and is presented on each
// job.
//
// teeBase is the TEE's root URL, e.g. http://127.0.0.1:18095.
func SealCredential(teeBase, provider string, secret tee.Secret) (tee.Envelope, error) {
	keyURL := strings.TrimSuffix(teeBase, "/") + "/v1/credential-key"
	pub, err := tee.CredentialKeyRequest(context.Background(), nil, keyURL)
	if err != nil {
		return tee.Envelope{}, fmt.Errorf("fetch inbox key: %w", err)
	}
	envelope, err := tee.EncryptCredential(pub, provider, secret)
	if err != nil {
		return tee.Envelope{}, fmt.Errorf("seal credential: %w", err)
	}
	return envelope, nil
}

// writePolicy encodes and writes a Hub-predefined whitelist policy to its
// per-provider path. The policy is unsigned: pricing lives in the Hub's rates.json
// (a commercial concern), and the whitelist itself is deployment config, whose
// integrity the TEE binds into its attestation measurement.
func writePolicy(provider string, p policy.Policy) error {
	enc, err := p.EncodeCanonical()
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

func policyPath() string { return filepath.Join(ConfigDir(), "policy.cbor") }
func policyPathFor(p string) string {
	if p == providerName {
		return policyPath()
	}
	return filepath.Join(ConfigDir(), "policies", p+".cbor")
}

// providerPolicy is the Hub-predefined whitelist the simulated TEE enforces
// for one provider. It is the real policy.Policy type — the simulation loads
// it through the genuine policy.Set, not a parallel hand-rolled structure.
// The two providers differ only in price, so the Hub's lowest-price scheduler
// has something to choose between; both point at the same upstream host.
//
// The whitelisted paths mirror the Hub's user-facing routes: the OpenAI chat
// completions endpoint, the OpenAI Responses endpoint, the Anthropic messages
// endpoint, and the streaming-session endpoint. In a real deployment these
// paths would live on different hosts per provider (api.openai.com vs
// api.anthropic.com); the simulation runs all shapes behind one mock host so
// a single Hub-predefined whitelist per provider covers all four routes.
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
	limits := policy.Limits{
		MaxResponseBytes: 1 << 20,
		MaxBodyBytes:     1 << 20,
		AllowedHeaders:   []string{"Content-Type"},
	}

	return policy.Policy{
		Version:   policy.VersionV1,
		Provider:  provider,
		Hosts:     hosts,
		Rules:     rules,
		Limits:    limits,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),
	}
}

// LoadPolicySet reads the primary provider's whitelist policy and installs it
// into a policy.Set. The policy is a Hub-predefined deployment document, not a
// provider signature, so it is installed via the unsigned path — the same
// Install call the real TEE uses for its deployment config.
func LoadPolicySet() (*policy.Set, error) {
	b, err := os.ReadFile(policyPath())
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p policy.Policy
	if err := canonical.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	set := policy.NewSet()
	if err := set.Install(p, time.Now()); err != nil {
		return nil, fmt.Errorf("install policy: %w", err)
	}
	return set, nil
}

// LoadPolicySetAll loads every installed provider policy: the primary
// policy.cbor plus any per-provider file under policies/. The real TEE uses
// this so that multi-provider scenarios see the whole supply; summaries that
// keep using LoadPolicySet are unaffected because the primary provider's
// policy is always included first.
func LoadPolicySetAll() (*policy.Set, error) {
	set := policy.NewSet()
	now := time.Now()

	paths := []string{policyPath()}
	extra, err := filepath.Glob(filepath.Join(ConfigDir(), "policies", "*.cbor"))
	if err != nil {
		return nil, fmt.Errorf("list policies dir: %w", err)
	}
	paths = append(paths, extra...)

	policies := make([]policy.Policy, 0, len(paths))
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", path, err)
		}
		var p policy.Policy
		if err := canonical.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("decode policy %s: %w", path, err)
		}
		policies = append(policies, p)
	}
	if err := set.InstallAll(policies, now); err != nil {
		return nil, fmt.Errorf("install policies: %w", err)
	}
	return set, nil
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
