//go:build !mobile

package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestExtractAttestationFromCert handles a cert that does and doesn't carry
// the attestation extension.
func TestExtractAttestationFromCert(t *testing.T) {
	t.Run("missing extension", func(t *testing.T) {
		cert := &x509.Certificate{}
		if _, err := ExtractAttestationFromCert(cert); err == nil {
			t.Fatal("expected error when extension absent")
		}
	})

	t.Run("extension present", func(t *testing.T) {
		want := []byte("attestation-payload-bytes")
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{
				{Id: AttestationOID, Value: want},
			},
		}
		got, err := ExtractAttestationFromCert(cert)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("extension value mismatch: got %q, want %q", got, want)
		}
	})
}

// fakeJWT produces a JWT-shaped string (header.payload.signature) where
// payload is the JSON-encoded claims. Signature is bogus but FindNonceValue
// doesn't inspect it — signature validity is the GoogleAttestor's concern,
// covered by separate tests.
func fakeJWT(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return hdr + "." + payload + ".sig"
}

func TestFindNonceValue(t *testing.T) {
	t.Run("string form", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": "tee_k_spki_hash:abcd1234"})
		got, err := FindNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if got != "abcd1234" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("array form picks matching prefix", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": []any{
			"tee_k_public_key:0xabc",
			"tee_k_spki_hash:cafef00d",
			"some_other:value",
		}})
		got, err := FindNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if got != "cafef00d" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("no matching prefix", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": "tee_k_public_key:0xabc"})
		_, err := FindNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err == nil {
			t.Fatal("expected error when no nonce matches prefix")
		}
	})

	t.Run("missing eat_nonce claim", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"sub": "something"})
		_, err := FindNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err == nil {
			t.Fatal("expected error when eat_nonce absent")
		}
	})

	t.Run("malformed JWT", func(t *testing.T) {
		_, err := FindNonceValue([]byte("not.a.jwt.at.all"), "x")
		if err == nil {
			t.Fatal("expected error on malformed JWT")
		}
		if !strings.Contains(err.Error(), "JWT") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("malformed base64 in payload", func(t *testing.T) {
		// Three segments, but the payload isn't valid base64url.
		_, err := FindNonceValue([]byte("hdr.!!!notb64!!!.sig"), "x")
		if err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("payload is not JSON", func(t *testing.T) {
		// Valid base64url but the decoded payload isn't JSON.
		jwt := base64.RawURLEncoding.EncodeToString([]byte("hdr")) +
			"." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) +
			".sig"
		_, err := FindNonceValue([]byte(jwt), "x")
		if err == nil {
			t.Fatal("expected unmarshal error")
		}
	})
}

// TestVerifyRATLSPeer_RejectsCertWithoutAttestationExtension proves that
// a peer cert lacking the AttestationOID extension is rejected — the
// "standalone-mode peers cannot talk RA-TLS" contract documented on
// VerifyRATLSPeer.
func TestVerifyRATLSPeer_RejectsCertWithoutAttestationExtension(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	// Local dev → no launcher socket → cert lacks extension. Confirm verifier
	// rejects it instead of crashing or silently passing.
	verify := VerifyRATLSPeer(RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: "sha256:anything",
	})
	err = verify([][]byte{m.CertificateRaw()}, nil)
	if err == nil {
		t.Fatal("expected error for cert without attestation extension")
	}
	if !strings.Contains(err.Error(), "extension") {
		t.Fatalf("expected extension-related error, got: %v", err)
	}
}

// TestVerifyRATLSPeer_RejectsGarbageAttestation builds a cert that DOES
// carry an extension under AttestationOID but with bytes that aren't a
// valid JWT. Verifier should fail at the JWT-validation step, not crash.
func TestVerifyRATLSPeer_RejectsGarbageAttestation(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tee_k"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: AttestationOID, Value: []byte("this is not a JWT")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	verify := VerifyRATLSPeer(RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: "sha256:anything",
	})
	err = verify([][]byte{der}, nil)
	if err == nil {
		t.Fatal("expected error for cert with garbage attestation bytes")
	}
}

// TestVerifyRATLSPeer_DispatchesToSEVSNP proves a cert carrying the SEV-SNP
// OID is routed to the SEV-SNP verifier (which rejects the garbage bytes),
// not the CS-JWT path or the "extension not present" branch.
func TestVerifyRATLSPeer_DispatchesToSEVSNP(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tee_k"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: AttestationOIDSEVSNP, Value: []byte("not a sev-snp report")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	verify := VerifyRATLSPeer(RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: "snp-measurement:anything",
	})
	err = verify([][]byte{der}, nil)
	if err == nil {
		t.Fatal("expected error for cert with garbage SEV-SNP bytes")
	}
	if strings.Contains(err.Error(), "extension not present") {
		t.Fatalf("dispatched to wrong branch (extension not found): %v", err)
	}
}

func TestVerifyRATLSPeer_PrefersSecureBootExtension(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tee_k"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: AttestationOIDSEVSNP, Critical: false, Value: []byte{snpAttestTagGCP}},
			// An unknown marker version must fail before the legacy proof. The
			// specific failure proves the updated verifier selected it first.
			{Id: AttestationOIDSecureBoot, Critical: false, Value: []byte{0xff}},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	err = VerifyRATLSAttestation("tee_k", nil)([][]byte{der}, nil)
	if err == nil || !strings.Contains(err.Error(), "Secure Boot extension version") {
		t.Fatalf("Secure Boot extension was not preferred: %v", err)
	}
}

func TestBaseAccepted(t *testing.T) {
	const gcp, aws = "snp-base:e51ea77d", "snp-base:48329081"
	set := gcp + "," + aws
	cases := []struct {
		expected, got string
		want          bool
	}{
		{set, gcp, true},
		{set, aws, true},
		{set, "snp-base:rogue", false},
		{gcp + " , " + aws, aws, true}, // tolerates spaces
		{gcp, aws, false},
		{set, "", false},
	}
	for _, c := range cases {
		if got := baseAccepted(c.expected, c.got); got != c.want {
			t.Errorf("baseAccepted(%q, %q) = %v, want %v", c.expected, c.got, got, c.want)
		}
	}
}
