// Package shared holds the small, reusable pieces the simulation binaries
// (mockprovider, faketee, hub, verify) share: the .sim working directory,
// the provider-credential and policy fixtures, the /v1/execute wire type, and
// a throwaway test CA so the TEE can talk real TLS to the mock provider.
//
// Nothing here is production code. It exists so the simulation runs end to end
// on a laptop with zero external dependencies and zero real credentials.
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

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
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

// PolicyRule is the whitelist the TEE enforces before touching a credential.
// It answers exactly one question: "is (scheme, host, path, method) allowed
// for this provider?"
type PolicyRule struct {
	Scheme  string   `json:"scheme"`
	Host    string   `json:"host"`
	Paths   []string `json:"paths"`
	Methods []string `json:"methods"`
}

// Policy maps a provider name to its whitelist.
type Policy map[string]PolicyRule

// ExecuteRequest is the body of POST /v1/execute: a canonical JobSpec plus the
// raw request bytes the TEE will send to the provider.
type ExecuteRequest struct {
	Spec jobs.Spec `cbor:"1,keyasint"`
	Body []byte    `cbor:"2,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of the request.
func (r ExecuteRequest) EncodeCanonical() ([]byte, error) { return canonical.Marshal(r) }

// DecodeExecuteRequest parses a canonical-CBOR ExecuteRequest.
func DecodeExecuteRequest(data []byte) (ExecuteRequest, error) {
	var r ExecuteRequest
	if err := canonical.Unmarshal(data, &r); err != nil {
		return ExecuteRequest{}, err
	}
	return r, nil
}

// EnsureDefaults writes the fixture files if they are missing so a bare `harness.sh`
// run works on a fresh checkout.
func EnsureDefaults() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "providers.json"), Providers{
		"openai-sim": "sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}); err != nil {
		return err
	}
	return writeIfAbsent(filepath.Join(dir, "policy.json"), Policy{
		"openai-sim": {
			Scheme:  "https",
			Host:    "127.0.0.1:18080",
			Paths:   []string{"/v1/chat/completions"},
			Methods: []string{"POST"},
		},
	})
}

// LoadProviders reads the provider-credential fixture.
func LoadProviders() (Providers, error) {
	var p Providers
	if err := readJSON(filepath.Join(ConfigDir(), "providers.json"), &p); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPolicy reads the whitelist fixture.
func LoadPolicy() (Policy, error) {
	var p Policy
	if err := readJSON(filepath.Join(ConfigDir(), "policy.json"), &p); err != nil {
		return nil, err
	}
	return p, nil
}

// CheckPolicy enforces the whitelist for one spec. It is the minimal TEE
// authorization the plan keeps inside the enclave: any (scheme, host, path,
// method) tuple not explicitly allowed is refused, and an http scheme is
// always refused so a credential can never traverse plaintext.
func CheckPolicy(rule PolicyRule, spec jobs.Spec) error {
	if rule.Scheme != "https" {
		return fmt.Errorf("provider policy requires https, got %q", rule.Scheme)
	}
	if spec.Method == "http" || spec.Host == "" {
		return fmt.Errorf("plaintext scheme rejected: credential must not leave the TEE unencrypted")
	}
	if rule.Host != spec.Host {
		return fmt.Errorf("host %q not allowed for provider (want %q)", spec.Host, rule.Host)
	}
	if !contains(rule.Methods, spec.Method) {
		return fmt.Errorf("method %q not allowed", spec.Method)
	}
	if !contains(rule.Paths, spec.Path) {
		return fmt.Errorf("path %q not allowed", spec.Path)
	}
	return nil
}

// WriteTEEIdentity persists the public identity of a sim epoch so the verifier
// (hub/verify) can resolve EvidenceHash without an inline attestation — exactly
// the "attestation cache" role a production verifier would fill from its own
// trust store.
func WriteTEEIdentity(id platform.Identity) error {
	return writeIfAbsentOrOverwrite(filepath.Join(ConfigDir(), "tee_identity.json"), id)
}

// LoadTEEIdentity reads the persisted public identity.
func LoadTEEIdentity() (platform.Identity, error) {
	var id platform.Identity
	if err := readJSON(filepath.Join(ConfigDir(), "tee_identity.json"), &id); err != nil {
		return platform.Identity{}, err
	}
	return id, nil
}

// CAPEMPath is where mockprovider drops its CA certificate for faketee to trust.
func CAPEMPath() string { return filepath.Join(ConfigDir(), "ca.pem") }

// GenCerts generates a throwaway CA and a server certificate for the loopback
// interface, returning a TLS config for the mock provider and the CA PEM for
// faketee to trust. No external tooling required.
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

// LoadCAPool reads the CA certificate mockprovider wrote, for faketee's TLS
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

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func writeIfAbsent(path string, v any) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return writeJSON(path, v)
}

func writeIfAbsentOrOverwrite(path string, v any) error { return writeJSON(path, v) }

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
