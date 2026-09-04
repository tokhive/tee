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
// ServerTLSConfig (RA-TLS certificates) — see the C4 checklist document for the
// exact wiring; this file's job is to expose the switches, not to guess at a
// deployment's certificate topology.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// defaultPlatform is what the harness and the local simulation use: a software
// attestation epoch whose evidence shape matches a real SEV-SNP report but
// whose trust root is just a generated key.
const defaultPlatform = "simulated"

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	relay := flag.String("relay", "", "Hub TeeRelay WebSocket URL: every provider connection egresses as a stream over the Hub's reverse tunnel")
	seqPath := flag.String("seq", "", "ProviderSeq store file (default <simdir>/seqstore.json)")
	platformName := flag.String("platform", defaultPlatform, "attestation platform: simulated or sevsnp")
	includeEvidence := flag.Bool("evidence", true, "embed attestation evidence in every receipt (false = resolve EvidenceHash via evidence retrieval)")
	caFile := flag.String("ca", "", "root CA PEM for provider TLS; empty = sim test CA on simulated, system roots on sevsnp")
	flag.Parse()

	// Fixtures are idempotent and live under TOKENHIVE_SIM_DIR (default .sim):
	// on a real deployment that directory is mounted by the provisioning path
	// with the operator's real provider policies and credentials instead. The
	// call is unconditional so the loader below never fails differently between
	// sim and cloud — only the file contents differ.
	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
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

	epoch, err := buildEpoch(*platformName, policySetHash)
	if err != nil {
		log.Fatalf("build platform epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
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
		Policies:  policies,
		Transport: cm,
		Signer:    signer,
		Seq:       store,
		InboxKey:  inbox,
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
	log.Printf("tee (platform=%s, includeEvidence=%t) listening on http://%s",
		*platformName, *includeEvidence, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
		pool, err := loadCAPath(caFile)
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

func loadCAPath(path string) (*x509.CertPool, error) {
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(der) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return pool, nil
}

// envOr returns the environment variable or a fallback. Used by the sevsnp
// build for the RA-TLS role name.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
