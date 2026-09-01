// Command tee is the simulated TEE built on the REAL tee.Service. It enforces
// the provider's signed policy, injects the credential, opens a real TLS
// connection to the provider (optionally egressing through a Provider Agent),
// and signs a receipt binding RequestBytes and the monotonic ProviderSeq.
//
// The only thing simulated is the attestation root: it uses
// platform/simulated instead of a real SEV-SNP enclave. proof.Signer and
// proof.Verify run unchanged, so every byte of the real execution path is
// exercised.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"path/filepath"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	agentAddr := flag.String("agent", "", "Provider Agent address; empty dials the provider directly over TLS")
	seqPath := flag.String("seq", "", "ProviderSeq store file (default <simdir>/seqstore.json)")
	flag.Parse()

	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	epoch, err := simulated.NewEpoch()
	if err != nil {
		log.Fatalf("create sim epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
	}

	policies, err := shared.LoadPolicySet()
	if err != nil {
		log.Fatalf("load policy set: %v", err)
	}

	creds := tee.NewStaticCredentials()
	providers, err := shared.LoadProviders()
	if err != nil {
		log.Fatalf("load providers: %v", err)
	}
	for p, tok := range providers {
		creds.Set(p, tok)
	}

	// Transport: real TLS to the provider, optionally tunneled through a
	// SOCKS5 Provider Agent. The TLS session terminates inside the TEE either
	// way, so the credential never exists on a wire the agent controls.
	tlsConfig, err := shared.LoadCAPool()
	if err != nil {
		log.Fatalf("load CA pool: %v", err)
	}
	trCfg := transport.Config{
		Scheme:          "https",
		TLSClientConfig: &tls.Config{RootCAs: tlsConfig},
	}
	if *agentAddr != "" {
		trCfg.DialContext = transport.SOCKS5Dialer(*agentAddr, nil)
	}
	tr, err := transport.New(trCfg)
	if err != nil {
		log.Fatalf("build transport: %v", err)
	}

	if *seqPath == "" {
		*seqPath = filepath.Join(shared.ConfigDir(), "seqstore.json")
	}
	store, err := tee.NewFileSeqStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	signer := proof.NewSigner(epoch)
	// Self-contained receipts so the offline verifier needs no external
	// attestation cache (see plan P0).
	signer.IncludeEvidence = true

	svc, err := tee.NewService(tee.Config{
		Policies:    policies,
		Credentials: creds,
		Transport:   tr,
		Signer:      signer,
		Seq:         store,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeExecute(svc, w, r)
	})
	log.Printf("tee (sim TEE, real service) listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
