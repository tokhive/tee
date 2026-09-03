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
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// microsPerUnit converts the rate card's integer micro-units into the units
// this binary prints. Only the display divides; every calculation stays in
// integers.
const microsPerUnit = 1_000_000

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
	audit := flag.Bool("audit", false, "audit the receipt store for gaps and verify signatures")
	flag.Parse()

	store := hub.NewReceiptStore(filepath.Join(shared.ConfigDir(), "receipts"))

	if *audit {
		runAudit(store, *provider)
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

	h, err := hub.New(hub.Config{
		TEE:                 &hub.HTTPTEE{URL: *teeURL + "/v1/execute", SessionURL: wsEndpoint(*teeURL, "/v1/session")},
		Rates:               rates,
		Store:               store,
		Verify:              verifyReceipt,
		Quota:               quota,
		Commission:          uint64(*commission),
		Withhold:            withholdSeq(*drop),
		SessionTimeout:      *sessionTimeout,
		SessionMaxDownBytes: *sessionMax,
		SessionIdle:         *sessionIdle,
	})
	if err != nil {
		log.Fatalf("build hub: %v", err)
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

func runAudit(store *hub.ReceiptStore, provider string) {
	report, err := store.Audit(provider, verifyReceipt)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	if report.Total == 0 {
		fmt.Printf("no receipts stored for provider %q\n", provider)
		return
	}
	fmt.Printf("verified %d/%d receipts for provider %q\n", report.Verified, report.Total, provider)

	// The deployment binding: receipts issued by a TEE deployed with the
	// current whitelist carry that policy-set hash in their evidence. When the
	// local deployment config exists, compare; receipts whose evidence lacks
	// the binding (issued by an unbound epoch) are flagged as warnings.
	expectedHash, haveDeployment := localPolicySetHash()
	if haveDeployment {
		fmt.Printf("expected deployment policy-set hash: %x\n", expectedHash)
	}

	// Evidence is checked separately from the signature: a receipt can be
	// perfectly signed and still point at an attestation that no longer
	// resolves, which is a cache problem rather than a forgery.
	receipts, err := store.List(provider)
	if err != nil {
		logf("list receipts: %v", err)
	}
	for _, signed := range receipts {
		id, err := signed.Receipt.Identity()
		if err != nil {
			fmt.Printf("  [WARN] seq=%d: identity: %v\n", signed.Receipt.ProviderSeq, err)
			continue
		}
		if haveDeployment {
			if err := simulated.CheckEvidenceForDeployment(id, expectedHash); err != nil {
				fmt.Printf("  [WARN] seq=%d: deployment binding: %v\n", signed.Receipt.ProviderSeq, err)
				continue
			}
			continue
		}
		if err := simulated.CheckEvidence(id); err != nil {
			fmt.Printf("  [WARN] seq=%d: evidence: %v\n", signed.Receipt.ProviderSeq, err)
		}
	}

	if report.Complete() {
		fmt.Printf("sequence complete: 1..%d, no gaps\n", report.MaxSeq)
		return
	}
	fmt.Printf(">>> GAP DETECTED: provider was used at least %d times but is missing receipts %v\n",
		report.MaxSeq, report.Missing)
}

// localPolicySetHash loads the deployment policy config the way cmd/tee does
// and returns the hash a correctly-deployed TEE would have bound into its
// evidence. haveDeployment is false when no policy config exists locally, in
// which case callers fall back to binding-free evidence checks.
func localPolicySetHash() (hash [32]byte, haveDeployment bool) {
	set, err := shared.LoadPolicySetAll()
	if err != nil {
		return hash, false
	}
	hash, err = set.Hash()
	if err != nil {
		logf("hash policy set: %v", err)
		return hash, false
	}
	return hash, true
}

// verifyReceipt checks a receipt's signature and attestation. The allowed
// platform list is the trust root; in the simulation it is the software epoch.
func verifyReceipt(signed proof.SignedReceipt) error {
	return proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}})
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
