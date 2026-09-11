// Command tee is the TokenHive TEE process. It enforces the provider's signed
// policy, injects the credential, opens a real TLS connection to the provider
// (optionally egressing through a Provider Agent), and signs a receipt binding
// RequestBytes and the monotonic ProviderSeq.
//
// It runs the REAL tee.Service on every execution path. What differs between
// the local simulation and a production deployment is only the assembly — the
// attestation platform, the receipt evidence policy, and the upstream TLS
// trust roots — and this binary exposes each of those as a switch so the same
// code serves both:
//
//	-platform simulated   software attestation epoch (default; local sim)
//	-platform sevsnp      AWS SEV-SNP RA-TLS epoch (real enclave). Compiled
//	                      only with `-tags sevsnp`; see epoch_sevsnp.go.
//	-evidence             embed attestation evidence in every receipt so each
//	                      one verifies offline (default true; the simulation
//	                      has no evidence cache to fetch from). Production sets
//	                      false and resolves EvidenceHash via the evidence
//	                      retrieval path (see the C4 checklist, §8).
//	-ca <path>            root CA PEM for the upstream (provider) TLS; empty in
//	                      sevsnp mode means the system trust store, which is
//	                      what production wants for api.openai.com etc. The
//	                      simulated default keeps loading the sim test CA so
//	                      the harness stays hermetic.
//
// The Hub↔TEE channel is deliberately separate: local sims run plain HTTP, and
// production enables mTLS at the listener using the platform adapter's
// ServerTLSConfig (RA-TLS certificates). -mtls switches the listener to that
// mode; -mtls-client-ca names the CA that signs Hub client certificates.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// defaultPlatform is what the harness and the local simulation use: a software
// attestation epoch whose evidence shape matches a real SEV-SNP report but
// whose trust root is just a generated key.
const defaultPlatform = "simulated"

func main() {
	// Under the measured loader the loader launches this binary twice: once as a
	// root-only attestation broker (which owns /dev/sev-guest, /dev/tpm0) and once
	// as the unprivileged app connected to it. When env marks this process as the
	// broker, serve attestation requests in a loop and exit instead of running the
	// TEE service (the same split tee_k/tee_t use).
	if broker, err := rootShared.RunSNPAttestationBrokerIfRequested(); broker {
		if err != nil {
			fmt.Fprintln(os.Stderr, "SNP attestation broker failed:", err)
			os.Exit(1)
		}
		return
	}

	// Every CLI flag falls back to an environment variable of the same semantics
	// so the measured app can be configured purely through the loader's instance-
	// metadata env injection (see deploy/snp-image/loader fetchMetadataEnv) with no
	// rebuild: the SHA-256-measured bundle stays byte-identical while runtime
	// routing (relay URL, ports, bootstrap token) comes from VM metadata.
	addr := flag.String("addr", envOr("TEE_ADDR", "127.0.0.1:18090"), "listen address")
	relay := flag.String("relay", envOr("TEE_RELAY", ""), "Hub TeeRelay WebSocket URL: every provider connection egresses as a stream over the Hub's reverse tunnel")
	// The relay key is part of the same env-driven surface: the measured app
	// authenticates to the Hub's TeeRelay with it, so a Hub that only admits an
	// authenticated egress path cannot be bypassed by anything that reaches the
	// listener, and the instance can be pointed at that Hub by metadata alone.
	relayKey := flag.String("relay-key", envOr("TEE_RELAY_KEY", ""), "key to present to the Hub's TeeRelay endpoint (empty = the Hub requires none)")
	maxConns := flag.Int("max-conns", envOrInt("TEE_MAX_CONNS", 0), "max resident provider connections per (provider, host) (0 = default 32)")
	requestTimeout := flag.Duration("request-timeout", envOrDuration("TEE_REQUEST_TIMEOUT", 2*time.Minute), "bound on a single provider exchange, including streaming sessions (0 = no bound)")
	seqPath := flag.String("seq", os.Getenv("TEE_SEQ"), "ProviderSeq store file (default <simdir>/seqstore.json)")
	platformName := flag.String("platform", envOr("TEE_PLATFORM", defaultPlatform), "attestation platform: simulated, sevsnp")
	includeEvidence := flag.Bool("evidence", envOrBool("TEE_EVIDENCE", true), "embed attestation evidence in every receipt (false = resolve EvidenceHash via evidence retrieval)")
	caFile := flag.String("ca", os.Getenv("TEE_CA"), "root CA PEM for provider TLS; empty = sim test CA on simulated, system roots on sevsnp")
	mtls := flag.Bool("mtls", envOrBool("TEE_MTLS", false), "serve the Hub-facing API over mutual TLS: the platform's RA-TLS server certificate (sevsnp) or the sim test certificate (simulated), demanding a Hub client certificate")
	mtlsClientCA := flag.String("mtls-client-ca", envOr("TEE_MTLS_CLIENT_CA", ""), "PEM CA(s) that sign Hub client certificates; empty defaults to <simdir>/hub-ca.pem (required with -mtls)")
	// Trust-on-first-use bootstrap: the confidential instance has no out-of-band
	// channel, so before the Hub can pin our RA-TLS certificate it must fetch it.
	// A one-shot plain-HTTP listener (gated by TEE_INIT_TOKEN) serves exactly that
	// leaf over GET /v1/init-cert and nothing else; the Hub never talks TLS to it.
	initAddr := flag.String("init-addr", envOr("TEE_INIT_ADDR", ""), "plain-HTTP bootstrap listener (e.g. 0.0.0.0:18091); serves /v1/init-cert gated by -init-token")
	initToken := flag.String("init-token", envOr("TEE_INIT_TOKEN", ""), "bearer token guarding the bootstrap /v1/init-cert endpoint (required with -init-addr)")
	flag.Parse()

	// Fixtures are idempotent and live under TOKENHIVE_SIM_DIR (default .sim):
	// on a real deployment that directory is mounted by the provisioning path
	// with the operator's real provider policies and credentials instead. The
	// call is unconditional so the loader below never fails differently between
	// sim and cloud — only the file contents differ.
	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}
	if *mtls {
		if err := shared.EnsureMTLSCerts(); err != nil {
			log.Fatalf("ensure mtls fixtures: %v", err)
		}
	}

	// The whitelist is part of this enclave's measured configuration: load it
	// before the epoch so its hash can be bound into the attestation evidence.
	// A receipt then proves not just "the trusted image ran" but "the trusted
	// image ran with exactly this policy set".
	policies, err := shared.LoadPolicySetAll()
	if err != nil {
		log.Fatalf("load policy set: %v", err)
	}
	policySetHash, err := policies.Hash()
	if err != nil {
		log.Fatalf("hash policy set: %v", err)
	}

	epoch, serverTLS, err := buildEpoch(*platformName, policySetHash)
	if err != nil {
		log.Fatalf("build platform epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
	}
	// Record this epoch's evidence in the restart-surviving store so a hash-only
	// receipt (IncludeEvidence=false) resolves against what the verifier saw, and
	// the /v1/evidence endpoint below can serve it to a Hub on another host.
	if err := shared.RecordTEEEvidence(epoch.Identity()); err != nil {
		log.Fatalf("record tee evidence: %v", err)
	}
	log.Printf("policy set hash bound into attestation evidence: %x", policySetHash)

	// The credential inbox: the TEE's own keypair for accepting agent-registered
	// tokens. The private half never leaves this process and nothing about it is
	// persisted, so a restart rotates the key and agents re-register with the
	// fresh public half. The TEE stores no access token at all: each job brings
	// its provider's token sealed to this key, and the private half is the only
	// way to open it.
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		log.Fatalf("generate inbox key: %v", err)
	}

	// Data path: real TLS to the provider over the Hub's reverse tunnel. The TLS
	// session terminates inside the TEE, so the credential never exists on a
	// wire the agent controls.
	upstreamTLS, err := upstreamTLSConfig(*platformName, *caFile)
	if err != nil {
		log.Fatalf("upstream TLS config: %v", err)
	}
	cm, err := transport.NewChannelManager(transport.ChannelConfig{
		Scheme:          "https",
		RelayURL:        *relay,
		RelayHeaders:    relayHeaders(*relayKey),
		MaxConnsPerHost: *maxConns,
		TLSClientConfig: upstreamTLS,
	})
	if err != nil {
		log.Fatalf("build channel manager: %v", err)
	}
	defer cm.Close()

	if *seqPath == "" {
		*seqPath = filepath.Join(shared.ConfigDir(), "seqstore.json")
	}
	store, err := tee.NewFileSeqStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	signer := proof.NewSigner(epoch)
	signer.IncludeEvidence = *includeEvidence

	svc, err := tee.NewService(tee.Config{
		Policies:       policies,
		Transport:      cm,
		Signer:         signer,
		Seq:            store,
		InboxKey:       inbox,
		RequestTimeout: *requestTimeout,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeExecute(svc, w, r)
	})
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeSession(svc, w, r)
	})
	// Credential plane: GET /v1/credential-key publishes the TEE's inbox public
	// key, which provider agents fetch (through the Hub) to encrypt their tokens
	// to. There is nothing else here — the TEE stores no token, so it has no
	// set/drop endpoints; envelopes live in the Hub's credential store and ride
	// onto each job.
	mux.HandleFunc("/v1/credential-key", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeCredentialKey(inbox, w, r)
	})
	// Evidence retrieval: serves the restart-surviving evidence store so a Hub
	// or auditor can resolve a hash-only receipt's EvidenceHash against a real
	// (possibly rotated) epoch this TEE presented. GET /v1/evidence/<hex-hash>
	// returns raw evidence bytes; GET /v1/evidence lists the stored hashes.
	evStore, err := shared.LoadEvidenceStore()
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	evidence.NewHTTPServer(evStore, mux)

	if *mtls {
		clientCAPath := *mtlsClientCA
		if clientCAPath == "" {
			clientCAPath = filepath.Join(shared.ConfigDir(), shared.MTLSClientCAPath)
		}
		if serverTLS == nil {
			log.Fatalf("platform %q provides no RA-TLS server certificate; cannot serve -mtls", *platformName)
		}
		cfg, err := shared.ServerMTLSConfig(serverTLS, clientCAPath)
		if err != nil {
			log.Fatalf("mtls server config: %v", err)
		}
		if err := shared.WriteTEECert(cfg); err != nil {
			log.Fatalf("publish tee certificate: %v", err)
		}
		// Trust-on-first-use bootstrap: hand the exact RA-TLS leaf we serve on the
		// mTLS plane to any caller that knows the token, so a Hub with no prior pin
		// can fetch and pin it. The listener is deliberately plain HTTP and serves
		// this single leaf-only endpoint — nothing else crosses it.
		if *initAddr != "" {
			go serveInitCert(*initAddr, *initToken, cfg)
		}
		log.Printf("tee (platform=%s, includeEvidence=%t, mtls) listening on https://%s",
			*platformName, *includeEvidence, *addr)
		server := &http.Server{Addr: *addr, Handler: mux, TLSConfig: cfg}
		log.Fatal(server.ListenAndServeTLS("", ""))
	}

	log.Printf("tee (platform=%s, includeEvidence=%t) listening on http://%s",
		*platformName, *includeEvidence, *addr)
	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		// ReadHeaderTimeout drops a client that stalls in the request line or
		// headers instead of pinning a connection. ReadTimeout and WriteTimeout
		// stay zero: /v1/session hijacks its connection into a long-lived
		// WebSocket, and /v1/execute answers with an SSE stream, so neither
		// endpoint has a bounded read or write window a deadline could safely
		// describe. The execute body itself is bounded inside ServeExecute.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// relayHeaders builds the headers the TEE presents when dialing the Hub's
// relay endpoint. An empty key means the Hub's relay requires none.
func relayHeaders(key string) http.Header {
	if key == "" {
		return nil
	}
	return http.Header{hub.RelayKeyHeader: {key}}
}

// upstreamTLSConfig returns the TLS trust roots for provider connections.
//
// The simulated platform loads the throwaway test CA mockprovider generates,
// keeping the local harness hermetic. sevsnp (production) uses the system
// trust store — api.openai.com and friends sign with public CAs — unless an
// explicit -ca file overrides it.
func upstreamTLSConfig(platformName, caFile string) (*tls.Config, error) {
	switch {
	case caFile != "":
		pool, err := shared.LoadCAPath(caFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool}, nil

	case platformName == "sevsnp":
		// System trust store: the ChannelManager treats a nil TLSClientConfig
		// as platform defaults, so nil is the explicit "system roots" choice.
		return nil, nil

	default:
		pool, err := shared.LoadCAPool()
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool}, nil
	}
}

// envOr returns the environment variable or a fallback. Used by the sevsnp
// build for the RA-TLS role name and for every flag's env default.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// envOrBool parses an environment variable as a boolean, falling back when it
// is unset (or not a valid boolean).
func envOrBool(name string, fallback bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// envOrInt parses an environment variable as an integer, falling back when it is
// unset (or not a valid integer). It keeps the connection cap configurable by
// instance metadata without a rebuild, like the other measured-app flags.
func envOrInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// envOrDuration parses an environment variable as a Go duration, falling back
// when it is unset (or not a valid duration).
func envOrDuration(name string, fallback time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// serveInitCert runs the TOFU bootstrap listener: a plain-HTTP server whose only
// handler is GET /v1/init-cert, protected by initToken. It returns exactly the
// RA-TLS leaf PEM the mTLS plane presents, so a Hub can pin it before the first
// mTLS exchange. The token gates who may read the attested identity; the leaf is
// public key material and holds nothing secret, but we keep the endpoint
// unauthenticated-scannable by requiring it.
func serveInitCert(addr, initToken string, mTLSConfig *tls.Config) {
	leaf, err := leafCertPEM(mTLSConfig)
	if err != nil {
		log.Fatalf("bootstrap: extract RA-TLS leaf: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/init-cert", func(w http.ResponseWriter, r *http.Request) {
		if initToken != "" && r.FormValue("token") != initToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(leaf)
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("bootstrap listener: %v", err)
	}
}

// leafCertPEM extracts the RA-TLS leaf certificate PEM from a server TLS config,
// mirroring what shared.WriteTEECert writes to disk (the same bytes the Hub pins).
func leafCertPEM(cfg *tls.Config) ([]byte, error) {
	var cert *tls.Certificate
	if cfg.GetCertificate != nil {
		c, err := cfg.GetCertificate(nil)
		if err != nil {
			return nil, err
		}
		cert = c
	} else if len(cfg.Certificates) > 0 {
		c := cfg.Certificates[0]
		cert = &c
	} else {
		return nil, fmt.Errorf("server TLS config has no certificate to serve")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse RA-TLS leaf: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), nil
}
