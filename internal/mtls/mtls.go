// Package mtls assembles the TLS configurations for the Hub↔TEE channel.
//
// The channel is deliberately deployment-wired: local sims run plain HTTP, and
// production enables mTLS at the TEE listener using the platform adapter's
// ServerTLSConfig (RA-TLS certificates). This package holds the certificate
// plumbing both sides share — the TEE-side listener config, the Hub-side pin,
// and the throwaway certificates the local simulation uses — so the wiring can
// be exercised end to end without a real enclave.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// PlatformServerTLS returns the RA-TLS server configuration the platform epoch
// provides, or nil when the platform has none. On sevsnp the adapter hands the
// attested RA-TLS config; on simulated the epoch mints a sim test certificate
// from its attested key.
func PlatformServerTLS(epoch platform.Epoch) *tls.Config {
	if s, ok := epoch.(interface{ ServerTLSConfig() *tls.Config }); ok {
		return s.ServerTLSConfig()
	}
	return nil
}

// ServerMTLSConfig assembles the TEE-side listener config for the Hub↔TEE
// channel: the RA-TLS leaf the platform provides as the server identity, plus
// a client-certificate demand rooted at the Hub CA. production passes the
// platform adapter's ServerTLSConfig (attested RA-TLS); the simulation passes
// the sim test certificate minted from the epoch key.
func ServerMTLSConfig(serverTLS *tls.Config, clientCAPath string) (*tls.Config, error) {
	pool, err := LoadCAPath(clientCAPath)
	if err != nil {
		return nil, err
	}
	cfg := serverTLS.Clone()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}

// ClientMTLSConfig assembles the Hub-side client config for the Hub↔TEE
// channel: it pins the TEE's RA-TLS certificate (or its signing CA) so the
// handshake proves the peer is the attested TEE, and presents the Hub's own
// client certificate so the TEE admits it. Either half may be omitted.
//
// The pin is verified with the standard chain check against the pool, but
// hostname verification is deliberately skipped: RA-TLS certificates are
// attested keys, not DNS identities, and the trust statement is "this exact
// certificate is the attested TEE", not "this hostname serves a public CA
// chain". Failing closed still holds — a peer outside the pin is rejected.
func ClientMTLSConfig(caPEMPath, certPath, keyPath string) (*tls.Config, error) {
	pool, err := LoadCAPath(caPEMPath)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // hostname check is irrelevant to RA-TLS pinning
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tee presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse tee certificate: %w", err)
			}
			intermediates := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					intermediates.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("tee certificate is not pinned: %w", err)
			}
			return nil
		},
	}
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, errors.New("cert and key must be set together")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// WriteTEECert publishes the leaf certificate a TEE listener presents, so the
// Hub (or the deployment tooling) can pin it. The certificate is extracted
// from the server TLS config the platform adapter produced: on sevsnp this is
// the attested RA-TLS leaf (its SPKI is the receipt KeyID), on simulated it is
// the sim test certificate minted from the epoch key.
func WriteTEECert(cfg *tls.Config, outPath string) error {
	var cert *tls.Certificate
	if cfg.GetCertificate != nil {
		c, err := cfg.GetCertificate(nil)
		if err != nil {
			return fmt.Errorf("read RA-TLS certificate: %w", err)
		}
		cert = c
	} else if len(cfg.Certificates) > 0 {
		c := cfg.Certificates[0]
		cert = &c
	} else {
		return errors.New("server TLS config has no certificate to publish")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse RA-TLS leaf: %w", err)
	}
	if err := os.WriteFile(outPath, pemEncode("CERTIFICATE", leaf.Raw), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}

// GenHubClientCerts generates a throwaway CA and a Hub client certificate
// signed by it. This is the Hub half of the local mTLS simulation: the TEE
// trusts the CA and demands a client cert, the Hub presents the client cert.
func GenHubClientCerts() (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "tokenhive-mtls-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "tokenhive-sim-hub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM = pemEncode("CERTIFICATE", caDER)
	certPEM = pemEncode("CERTIFICATE", cliDER)
	keyPEM = pemEncode("EC PRIVATE KEY", mustMarshalEC(cliKey))
	return caPEM, certPEM, keyPEM, nil
}

// GenMockProviderCerts generates a throwaway CA and a server certificate for
// the mock AI provider. The CA is what the TEE must trust for the upstream TLS
// leg; it is baked into the measured bundle (TEE_CA) so a real TEE on another
// host can validate the provider without the CA crossing the no-sshd boundary
// at runtime, while the cert/key deploy with the mock provider process.
func GenMockProviderCerts() (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(201),
		Subject:               pkix.Name{CommonName: "tokenhive-sim-provider-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(202),
		Subject:      pkix.Name{CommonName: "tokenhive-sim-provider"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM = pemEncode("CERTIFICATE", caDER)
	certPEM = pemEncode("CERTIFICATE", srvDER)
	keyPEM = pemEncode("EC PRIVATE KEY", mustMarshalEC(srvKey))
	return caPEM, certPEM, keyPEM, nil
}

// LoadCAPath reads a PEM file into a certificate pool.
func LoadCAPath(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
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
