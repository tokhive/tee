package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUpstreamTLSConfigAddsCARatherThanReplacing is the regression guard for the
// failure mode where a TEE configured with one extra CA (TEE_CA, the
// mock-provider CA baked into the measured bundle) could not validate ANY real
// provider: crypto/tls gives a non-nil RootCAs pool the place of the system
// trust store, so naming one CA removed every other anchor. The symptom is a
// handshake that sends only a ClientHello and dies in certificate verification,
// which the Hub reports as a closed stream and a byte count — nothing in that
// signal says "trust store", so only a test can hold the line.
func TestUpstreamTLSConfigAddsCARatherThanReplacing(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	// The platform's own root: on the simulated platform this is the throwaway
	// CA mockprovider writes to <simdir>/ca.pem, and it stands in for the
	// system store a sevsnp TEE gets from the loader's SSL_CERT_FILE.
	platformCA, platformLeaf := mintCA(t, "platform-ca", "provider")
	if err := os.WriteFile(filepath.Join(simDir, "ca.pem"), platformCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	// The extra CA a deployment points -ca/TEE_CA at.
	extraCA, extraLeaf := mintCA(t, "extra-ca", "extra-provider")
	extraPath := filepath.Join(t.TempDir(), "extra-ca.pem")
	if err := os.WriteFile(extraPath, extraCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := upstreamTLSConfig("simulated", extraPath)
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("an extra CA must produce a pool, not the platform default")
	}
	// The whole point of the fix: the platform's root SURVIVES the extra CA.
	assertTrusts(t, "platform root, with -ca given", cfg.RootCAs, platformLeaf)
	assertTrusts(t, "extra CA, with -ca given", cfg.RootCAs, extraLeaf)

	// Without the flag the extra CA must not be trusted, so the assertions above
	// cannot pass for the wrong reason.
	plain, err := upstreamTLSConfig("simulated", "")
	if err != nil {
		t.Fatalf("upstreamTLSConfig(simulated, \"\"): %v", err)
	}
	if plain == nil || plain.RootCAs == nil {
		t.Fatal("the simulated platform must still carry its own test CA")
	}
	assertTrusts(t, "platform root, no -ca", plain.RootCAs, platformLeaf)
	assertRejects(t, "extra CA, no -ca", plain.RootCAs, extraLeaf)

	// sevsnp carries the system store — the loader's SSL_CERT_FILE bundle —
	// whatever -ca says, and neither the sim platform's CA nor the extra CA is
	// part of it.
	snp, err := upstreamTLSConfig("sevsnp", "")
	if err != nil {
		t.Fatalf("upstreamTLSConfig(sevsnp, \"\"): %v", err)
	}
	if snp == nil || snp.RootCAs == nil {
		t.Fatal("sevsnp must carry the system trust store, not defer to a nil config")
	}
	assertRejects(t, "sim platform CA on sevsnp", snp.RootCAs, platformLeaf)
	assertRejects(t, "extra CA on sevsnp", snp.RootCAs, extraLeaf)
}

// TestAppendCAPathRejectsAnEmptyBundle: a trust-anchor path that parses to
// nothing is an error, never a silent no-op that changes which certificates the
// TEE accepts.
func TestAppendCAPathRejectsAnEmptyBundle(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamTLSConfig("sevsnp", empty); err == nil {
		t.Fatal("a CA file with no certificate must be refused")
	}
}

func assertTrusts(t *testing.T, what string, roots *x509.CertPool, leaf *x509.Certificate) {
	t.Helper()
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("%s: expected to verify, got %v", what, err)
	}
}

func assertRejects(t *testing.T, what string, roots *x509.CertPool, leaf *x509.Certificate) {
	t.Helper()
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Errorf("%s: expected verification to fail", what)
	}
}

type testCA struct {
	pem []byte
	key *ecdsa.PrivateKey
}

// mintCA returns a self-signed CA and a localhost server leaf signed by it.
func mintCA(t *testing.T, caCN, leafCN string) (testCA, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), key: caKey}, leaf
}
