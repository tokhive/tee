package integration

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// newMTLSServer runs the REAL tee.Service over a real mTLS listener: the
// simulated epoch's RA-TLS-shaped certificate as the server identity, and a
// throwaway Hub CA that must sign the client certificate. It returns the
// server, the sealed credential the Hub must attach to jobs, and the paths of
// the Hub's mTLS identity files (the TEE pin, the Hub cert, the Hub key).
func newMTLSServer(t *testing.T, transport tee.Transport) (*httptest.Server, []byte, string, string, string) {
	t.Helper()

	epoch, err := simulated.NewDeploymentEpoch([32]byte{})
	if err != nil {
		t.Fatalf("sim epoch: %v", err)
	}
	policies := policy.NewSet()
	if err := policies.Install(openAIPolicy(), now); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("inbox key: %v", err)
	}
	service, err := tee.NewService(tee.Config{
		Policies:  policies,
		Transport: transport,
		Signer:    proof.NewSigner(epoch),
		Clock:     func() time.Time { return now },
		Seq:       tee.NewMemorySeqStore(),
		InboxKey:  inbox,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	env, err := tee.EncryptCredential(inbox.Public(), "openai",
		tee.Secret{Token: "sk-mtls-token", Header: "authorization", Scheme: "Bearer"})
	if err != nil {
		t.Fatalf("seal credential: %v", err)
	}
	cred, err := env.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode credential: %v", err)
	}

	// The Hub's mTLS identity: a throwaway CA (which the TEE trusts) and a
	// client certificate it signs (which the Hub presents).
	caPEM, certPEM, keyPEM, err := mtls.GenHubClientCerts()
	if err != nil {
		t.Fatalf("hub client certs: %v", err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "hub-ca.pem")
	certFile := filepath.Join(dir, "hub-client.pem")
	keyFile := filepath.Join(dir, "hub-client-key.pem")
	for path, data := range map[string][]byte{caFile: caPEM, certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	serverCfg, err := mtls.ServerMTLSConfig(mtls.PlatformServerTLS(epoch), caFile)
	if err != nil {
		t.Fatalf("server mtls config: %v", err)
	}
	// The TEE's RA-TLS leaf is the thing the Hub pins: the deployment's
	// out-of-band statement that this certificate is the attested TEE.
	teeCertFile := filepath.Join(dir, "tee-cert.pem")
	if err := mtls.WriteTEECert(serverCfg, teeCertFile); err != nil {
		t.Fatalf("write tee cert: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeExecute(service, w, r)
	})
	server := httptest.NewUnstartedServer(mux)
	server.TLS = serverCfg
	server.StartTLS()
	t.Cleanup(server.Close)

	return server, cred, teeCertFile, certFile, keyFile
}

// TestHubTalksToTEEOverMutualTLS proves the full Hub↔TEE mTLS wiring: a TEE
// listener that demands a Hub client certificate, a Hub client that pins the
// TEE's RA-TLS certificate and presents its own identity, and a receipt that
// verifies once the channel is up.
func TestHubTalksToTEEOverMutualTLS(t *testing.T) {
	server, cred, caFile, certFile, keyFile := newMTLSServer(t, &scriptedTransport{
		statusCode: 200,
		chunks: [][]byte{
			[]byte(`data: {"choices":[{"delta":{"content":"Hi"}}]}`),
			[]byte(`data: {"choices":[{"delta":{"content":" from the mtls TEE"}}]}`),
			[]byte(`data: [DONE]`),
		},
	})

	clientCfg, err := mtls.ClientMTLSConfig(caFile, certFile, keyFile)
	if err != nil {
		t.Fatalf("client mtls config: %v", err)
	}
	teeClient := &hub.HTTPTEE{
		URL:    server.URL + "/v1/execute",
		Client: &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}},
	}

	spec, body := chatCompletion(t)
	spec.Credential = cred
	result, err := teeClient.Execute(context.Background(), spec, body, nil)
	if err != nil {
		t.Fatalf("execute over mtls: %v", err)
	}

	encoded, err := result.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	if _, err := proof.DecodeAndVerify(encoded, proof.VerifyOptions{
		Now:              now.Add(time.Minute),
		AllowedPlatforms: []string{simulated.Platform},
		MaxAge:           time.Hour,
	}); err != nil {
		t.Fatalf("verify receipt from mtls tee: %v", err)
	}
	if len(result.Chunks) == 0 {
		t.Fatal("no chunks relayed over mtls")
	}
}

// TestMTLSRejectsHubWithoutClientIdentity is the fail-closed half: a Hub that
// pins the TEE certificate but presents no client certificate is refused at
// the handshake — the TEE must not admit unauthenticated peers.
func TestMTLSRejectsHubWithoutClientIdentity(t *testing.T) {
	server, cred, caFile, _, _ := newMTLSServer(t, &scriptedTransport{
		statusCode: 200,
		chunks:     [][]byte{[]byte(`data: [DONE]`)},
	})

	pinOnly, err := mtls.ClientMTLSConfig(caFile, "", "")
	if err != nil {
		t.Fatalf("pin-only config: %v", err)
	}
	teeClient := &hub.HTTPTEE{
		URL:    server.URL + "/v1/execute",
		Client: &http.Client{Transport: &http.Transport{TLSClientConfig: pinOnly}},
	}

	spec, body := chatCompletion(t)
	spec.Credential = cred
	if _, err := teeClient.Execute(context.Background(), spec, body, nil); err == nil {
		t.Fatal("hub without a client certificate was admitted over mtls")
	}
}

// TestMTLSRejectsUnpinnedTEE is the other fail-closed half: a Hub that trusts
// nothing cannot complete a handshake with the TEE's self-signed RA-TLS
// certificate.
func TestMTLSRejectsUnpinnedTEE(t *testing.T) {
	server, cred, _, _, _ := newMTLSServer(t, &scriptedTransport{
		statusCode: 200,
		chunks:     [][]byte{[]byte(`data: [DONE]`)},
	})

	teeClient := &hub.HTTPTEE{URL: server.URL + "/v1/execute"} // default client, no pin
	spec, body := chatCompletion(t)
	spec.Credential = cred
	if _, err := teeClient.Execute(context.Background(), spec, body, nil); err == nil {
		t.Fatal("unpinned TEE was accepted over mtls")
	}
}

// TestMTLSServerCertificateMatchesAttestedIdentity is the property that makes
// RA-TLS pinning meaningful: the certificate the TEE serves was minted from
// the same key the attestation evidence names, so the SPKI the Hub pins is the
// SPKI a receipt later proves. A certificate from a different epoch must not
// satisfy the pin.
func TestMTLSServerCertificateMatchesAttestedIdentity(t *testing.T) {
	epoch, err := simulated.NewDeploymentEpoch([32]byte{})
	if err != nil {
		t.Fatalf("sim epoch: %v", err)
	}
	identity := epoch.Identity()

	cfg := mtls.PlatformServerTLS(epoch)
	var leaf *x509.Certificate
	switch {
	case cfg.GetCertificate != nil:
		c, err := cfg.GetCertificate(nil)
		if err != nil {
			t.Fatalf("get server certificate: %v", err)
		}
		leaf, err = x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
	case len(cfg.Certificates) > 0:
		c, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		leaf = c
	default:
		t.Fatal("server config has no certificate")
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatalf("marshal leaf SPKI: %v", err)
	}
	if sha256.Sum256(spki) != identity.KeyID {
		t.Fatal("served certificate SPKI does not match the attested identity KeyID")
	}
}
