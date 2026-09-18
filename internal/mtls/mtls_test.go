package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestFixtureCertsAreLongLivedAndChain pins the two properties the throwaway
// fixture set has to have. Both matter to the cross-host cloudtest, which bakes
// these very bytes into a measured bundle and deploys the halves to different
// machines: a window of hours makes a fixture expire in the middle of an
// experiment, and a leaf is only usable beside the CA that signed it — with the
// CA outliving its leaves, so re-signing one never disturbs a deployment that
// already pinned the CA.
func TestFixtureCertsAreLongLivedAndChain(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func() (caPEM, certPEM, keyPEM []byte, err error)
	}{
		{"hub client", GenHubClientCerts},
		{"mock provider", GenMockProviderCerts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caPEM, certPEM, _, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			ca := parseCert(t, caPEM)
			cert := parseCert(t, certPEM)

			if now := time.Now(); cert.NotAfter.Before(now.Add(365 * 24 * time.Hour)) {
				t.Errorf("leaf expires %v from now; a fixture must outlast the experiment it belongs to",
					cert.NotAfter.Sub(now))
			}
			if ca.NotAfter.Before(cert.NotAfter) {
				t.Errorf("CA expires %v, before the leaf it signed (%v)", ca.NotAfter, cert.NotAfter)
			}

			// Chain only — the leaf's own key usage (client auth for the Hub,
			// server auth for the provider) is not what is being pinned here.
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			if _, err := cert.Verify(x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				t.Fatalf("leaf does not chain to the CA minted beside it: %v", err)
			}
		})
	}
}

func parseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(der)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
