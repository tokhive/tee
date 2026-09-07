// Command hub is the business side of TokenHive. It builds a JobSpec (without
// ever seeing the provider credential), calls the TEE's /v1/execute, forwards
// the streamed response to the "user", and settles the result.
//
// All of the business rules live in the hub package; this binary is only the
// wiring and the printing. That split is deliberate: the rules are the part
// that changes, and they are tested in-process against a scripted TEE, far
// from any flag parsing.
//
// Flags:
//
//	-audit        scan the receipt store, cryptographically verify every
//	              receipt, and report any ProviderSeq gaps
//	-drop N       withhold the receipt carrying ProviderSeq N from the store
//	              (simulates a Hub that hides a record from the provider)
//	-quota N      cap a tenant at N requests per -window (0 = unlimited)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/attest"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// microsPerUnit converts the rate card's integer micro-units into the units
// this binary prints. Only the display divides; every calculation stays in
// integers.
const microsPerUnit = 1_000_000

// evidenceCache resolves full attestation evidence for hash-only receipts this
// process has seen, layered on top of the restart-surviving evidence store the
// TEE publishes. A receipt carrying only an evidence hash resolves against what
// the Hub actually observed or the TEE recorded; the Hub never trusts an epoch
// it has not seen evidence for.
var evidenceCache attest.Cache

func main() {
	teeURL := flag.String("tee", "http://127.0.0.1:18090", "TEE base URL")
	serveAddr := flag.String("serve", "", "run as the OpenAI-compatible HTTP service on this address (empty = one-shot CLI mode)")
	provider := flag.String("provider", "openai-sim", "provider name")
	host := flag.String("host", "127.0.0.1:18080", "provider host:port (must match policy)")
	model := flag.String("model", "sim-mock-0.5b", "declared model (opaque to TEE)")
	query := flag.String("query", "", "provider URL query, e.g. fault=401|429|truncate|slow|big")
	tenant := flag.String("tenant", "tenant-demo-001", "tenant the request is attributed to for quota")
	maxBytes := flag.Uint64("max", 1<<20, "MaxResponseBytes cap sent to the TEE (bytes)")
	n := flag.Int("n", 1, "number of requests to send")
	commission := flag.Int("commission", 0, "Hub commission in basis points (100 = 1%)")
	drop := flag.Int("drop", 0, "withhold the receipt with this ProviderSeq from the store (0 = none)")
	quotaLimit := flag.Int64("quota", 0, "max requests per tenant per window (0 = unlimited)")
	quotaWindow := flag.Duration("window", time.Minute, "quota window")
	sessionTimeout := flag.Duration("session-timeout", 10*time.Minute, "max wall-clock lifetime of a streaming session (0 = unlimited)")
	sessionMax := flag.Uint64("session-max", 1<<20, "max downlink bytes a streaming session may relay (0 = unlimited)")
	sessionIdle := flag.Duration("session-idle", 30*time.Second, "tear a session down if the provider streams nothing this long (0 = no watchdog)")
	agentKey := flag.String("agent-key", "", "shared key Provider Agents must present to dial in (required to make the Hub schedulable-by-online)")
	credential := flag.String("credential", "", "provider access token to register with the TEE before the request loop (simulation one-shot mode: the CLI holds the seller's token and delivers it sealed to -tee, as a dialing agent would through a resident Hub)")
	audit := flag.Bool("audit", false, "audit the receipt store for gaps and verify signatures")
	allowed := flag.String("allowed-platforms", "simulated", "comma-separated attestation platforms the Hub trusts (e.g. simulated,aws-sev-snp)")
	expectedApp := flag.String("expected-app", "", "for aws-sev-snp: the attested application identity the deployment trusts (snp-app:<sha256 hex>)")
	policyHash := flag.String("policy-set-hash", "", "hex digest the enclave must have bound into its evidence; empty skips the deployment-binding assertion (the Hub pins the platform, not the exact policy digest, at runtime)")
	evFetchURL := flag.String("evidence-fetch", "", "base URL for remote evidence retrieval (e.g. https://tee:18090); empty = resolve EvidenceHash from the local evidence store only")
	flag.Parse()

	store := hub.NewReceiptStore(filepath.Join(shared.ConfigDir(), "receipts"))

	if *audit {
		runAudit(store, *provider, *allowed, *expectedApp, *policyHash, *evFetchURL)
		return
	}

	// The Hub's market table: seller-reported prices. The whitelist policy is
	// a TEE concern and never reaches the Hub — the Hub prices from its own
	// rates, not from what the TEE will authorise.
	rates, err := shared.LoadRates()
	if err != nil {
		log.Fatalf("load rates: %v", err)
	}

	var quota *hub.Quota
	if *quotaLimit > 0 {
		quota, err = hub.NewQuota(*quotaLimit, *quotaWindow)
		if err != nil {
			log.Fatalf("quota: %v", err)
		}
	}

	teeClient := &hub.HTTPTEE{
		URL:        *teeURL + "/v1/execute",
		SessionURL: wsEndpoint(*teeURL, "/v1/session"),
		BaseURL:    *teeURL,
	}
	verifier, err := buildVerifier(*allowed, *expectedApp, *policyHash, *evFetchURL)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}
	h, err := hub.New(hub.Config{
		TEE:                 teeClient,
		Rates:               rates,
		Store:               store,
		Verify:              verifier.VerifyFunc(),
		Quota:               quota,
		Commission:          uint64(*commission),
		Withhold:            withholdSeq(*drop),
		SessionTimeout:      *sessionTimeout,
		SessionMaxDownBytes: *sessionMax,
		SessionIdle:         *sessionIdle,
		AgentSecret:         []byte(*agentKey),
		Credentials:         teeClient,
	})
	if err != nil {
		log.Fatalf("build hub: %v", err)
	}

	// One-shot mode talks to the TEE directly, so it delivers the credential
	// itself (the resident serve mode receives it through dialing agents
	// instead). Defaults mirror what the provider agent applies: Bearer over
	// the authorization header.
	if *credential != "" && *serveAddr == "" {
		if err := h.RegisterCredential(context.Background(), *provider, tee.Secret{
			Token:  *credential,
			Header: "authorization",
			Scheme: "Bearer",
		}); err != nil {
			log.Fatalf("register credential: %v", err)
		}
	}

	// Resident user-facing mode: one OpenAI-compatible HTTP endpoint that routes
	// by model through the lowest-price scheduler.
	if *serveAddr != "" {
		runServe(h, serveConfig{
			Addr:  *serveAddr,
			Host:  *host,
			Query: *query,
			Max:   *maxBytes,
		})
		return
	}

	body := []byte(`{"model":"` + *model + `","messages":[{"role":"user","content":"你是谁？"}],"stream":true}`)
	ctx := context.Background()

	for i := 1; i <= *n; i++ {
		fmt.Printf("\n=== request %d/%d ===\n", i, *n)
		spec, err := buildSpec(*provider, *host, "/v1/chat/completions", *query, body, *maxBytes)
		if err != nil {
			logf("build spec: %v", err)
			continue
		}
		outcome, err := h.Execute(ctx, *tenant, *model, spec, body, func(chunk []byte) error {
			fmt.Printf("[user sees] %s\n", chunk)
			return nil
		})
		if err != nil {
			logf("request: %v", err)
			continue
		}
		printOutcome(outcome)
	}
	printLedger(h.Ledger())
}

// wsEndpoint rewrites the TEE's http(s) base into the ws(s) WebSocket URL its
// /v1/session endpoint needs. The user passes one teeURL; keeping the session
// endpoint derived from it (rather than a second flag) means the two can never
// drift, and the scheme swap is the only difference gorilla/websocket rejects.
func wsEndpoint(base, path string) string {
	if strings.HasPrefix(base, "https://") {
		return "wss://" + strings.TrimPrefix(base, "https://") + path
	}
	return "ws://" + strings.TrimPrefix(base, "http://") + path
}

func printOutcome(outcome hub.Outcome) {
	r := outcome.Receipt.Receipt
	fmt.Printf("[receipt] provider=%s seq=%d requestBytes=%d responseBytes=%d chunks=%d status=%d completion=%s charged=%.2f commission=%.2f buyer=%.2f\n",
		r.Provider, r.ProviderSeq, r.RequestBytes, r.ResponseBytes, r.ChunkCount,
		r.StatusCode, r.Completion, float64(outcome.Charged)/microsPerUnit,
		float64(outcome.Commission)/microsPerUnit, float64(outcome.Buyer)/microsPerUnit)
	if !outcome.Stored {
		fmt.Printf("[withhold] receipt seq=%d kept out of the provider's store\n", r.ProviderSeq)
	}
}

func printLedger(ledger *hub.Ledger) {
	snap := ledger.Snapshot()
	fmt.Printf("\n--- ledger ---\n")
	fmt.Printf("requests dispatched : %d\n", snap.Dispatched)
	fmt.Printf("receipts verified  : %d\n", snap.Verified)
	fmt.Printf("receipts settled   : %d\n", snap.Settled)
	fmt.Printf("provider revenue   : %.2f units (price is provider-owned)\n",
		float64(snap.Revenue)/microsPerUnit)
	fmt.Printf("hub commission     : %.2f units\n",
		float64(snap.Commission)/microsPerUnit)
	for provider, account := range snap.ByProvider {
		fmt.Printf("  %s : %d settled, %.2f units (+%.2f commission)\n",
			provider, account.Settled, float64(account.Revenue)/microsPerUnit,
			float64(account.Commission)/microsPerUnit)
	}
}

func runAudit(store *hub.ReceiptStore, provider, allowed, expectedApp, policyHash, evFetchURL string) {
	verifier, err := buildVerifier(allowed, expectedApp, policyHash, evFetchURL)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}
	report, err := store.Audit(provider, verifier.VerifyFunc())
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	if report.Total == 0 {
		fmt.Printf("no receipts stored for provider %q\n", provider)
		return
	}
	fmt.Printf("verified %d/%d receipts for provider %q (allowed platforms: %v)\n",
		report.Verified, report.Total, provider, verifier.AllowedPlatforms())

	if report.Complete() {
		fmt.Printf("sequence complete: 1..%d, no gaps\n", report.MaxSeq)
		return
	}
	fmt.Printf(">>> GAP DETECTED: provider was used at least %d times but is missing receipts %v\n",
		report.MaxSeq, report.Missing)
}

// buildVerifier assembles the attestation trust root from the operator's
// allowlist. A platform the operator advertises as trusted but that has no
// evidence verifier wired here is a wiring error and fails loudly at startup,
// not at the first receipt.
func buildVerifier(allowed, expectedApp, policyHash, evFetchURL string) (*attest.Verifier, error) {
	lists, err := splitCSV(allowed)
	if err != nil {
		return nil, err
	}
	byPlatform := map[string]platform.EvidenceVerifier{
		simulated.Platform: simulated.Verifier{},
		platform.PlatformAWSSEVSNP: sevsnp.Verifier{
			ExpectedApp: expectedApp,
		},
	}
	fetcher, err := buildFetcher(evFetchURL)
	if err != nil {
		return nil, err
	}
	cfg := attest.Config{
		AllowedPlatforms: lists,
		ByPlatform:       byPlatform,
		Fetcher:          fetcher,
	}
	// The deployment binding is opt-in. At runtime the Hub pins the platform
	// trust root, not the exact policy digest: policy files are rewritten with a
	// fresh IssuedAt on every startup, so deriving the hash here would race the
	// TEE's own binding and reject valid receipts. An operator who wants the
	// strongest bound (prove the enclave ran a specific whitelist config)
	// passes the digest explicitly.
	if policyHash != "" {
		h, err := hex.DecodeString(policyHash)
		if err != nil {
			return nil, fmt.Errorf("parse -policy-set-hash: %w", err)
		}
		if len(h) != 32 {
			return nil, fmt.Errorf("-policy-set-hash must be a 32-byte hex digest, got %d bytes", len(h))
		}
		copy(cfg.PolicySetHash[:], h)
	}
	return attest.New(cfg)
}

// splitCSV splits a comma-separated allowlist, trimming whitespace.
func splitCSV(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty -allowed-platforms")
	}
	return out, nil
}

// buildFetcher assembles the evidence retrieval path in resolution order: the
// in-memory cache of epochs this process has verified, then the restart-surviving
// local store, then an optional remote /v1/evidence endpoint. Each layer is
// tried in turn until one holds the bytes.
func buildFetcher(evFetchURL string) (attest.Fetcher, error) {
	backend := &evidence.Chain{}
	backend.Add(&evidenceCache)
	if store, err := shared.LoadEvidenceStore(); err == nil {
		backend.Add(store)
	}
	if evFetchURL != "" {
		httpFetcher, err := evidence.NewHTTPFetcher(evFetchURL)
		if err != nil {
			return nil, err
		}
		backend.Add(httpFetcher)
	}
	return backend, nil
}

// withholdSeq models a Hub that hides one execution from the provider. The
// point of the exercise is that hiding it still leaves a numbered hole.
func withholdSeq(seq int) func(uint64) bool {
	if seq <= 0 {
		return nil
	}
	target := uint64(seq)
	return func(seq uint64) bool { return seq == target }
}

func buildSpec(provider, host, path, query string, body []byte, maxBytes uint64) (jobs.Spec, error) {
	jobID := make([]byte, jobs.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		return jobs.Spec{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return jobs.Spec{}, err
	}
	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            jobID,
		Provider:         provider,
		Method:           "POST",
		Host:             host,
		Path:             path,
		Query:            query,
		Headers:          map[string]string{"Content-Type": "application/json"},
		BodyHash:         hashBodyBytes(body),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: maxBytes,
		Stream:           true,
	}, nil
}

func hashBodyBytes(body []byte) []byte {
	h := jobs.HashBody(body)
	return h[:]
}

func logf(format string, args ...any) { fmt.Printf("[hub] "+format+"\n", args...) }
