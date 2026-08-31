// Command hub is the business side of TokenHive. It builds a JobSpec (without
// ever seeing the provider credential), calls the TEE's /v1/execute, forwards
// the streamed response to the "user", and collects the signed receipt.
//
// On a verified receipt it:
//   - writes the receipt into the per-provider receipt store (the artifact a
//     provider would audit — enabling ProviderSeq gap detection)
//   - credits the provider's ledger using a price taken from the provider's
//     own policy (pricing authority lives with the provider, per the plan)
//   - checks the receipt's StreamHash against the bytes actually forwarded
//
// Flags:
//   -audit        scan the receipt store, cryptographically verify every
//                 receipt, and report any ProviderSeq gaps
//   -drop N       withhold the Nth receipt from the store (simulates a Hub
//                 that hides a record from the provider)
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/sim/internal/shared"
)

// pricePerRequest is the provider's own price table. In the plan, pricing
// authority lives with the provider: this map stands in for the rate card a
// provider would sign into its Policy. The Hub merely applies it.
var pricePerRequest = map[string]float64{
	"openai-sim": 1.0,
}

func main() {
	teeURL := flag.String("tee", "http://127.0.0.1:18090", "faketee (sim TEE) base URL")
	provider := flag.String("provider", "openai-sim", "provider name")
	host := flag.String("host", "127.0.0.1:18080", "provider host:port (must match policy)")
	model := flag.String("model", "sim-mock-0.5b", "declared model (opaque to TEE)")
	query := flag.String("query", "", "provider URL query, e.g. fault=401|429|truncate")
	n := flag.Int("n", 1, "number of requests to send")
	drop := flag.Int("drop", 0, "withhold the Nth receipt from the store (0 = withhold none)")
	audit := flag.Bool("audit", false, "audit the receipt store for gaps and verify signatures")
	flag.Parse()

	if *audit {
		runAudit(*provider)
		return
	}

	body := []byte(`{"model":"` + *model + `","messages":[{"role":"user","content":"你是谁？"}],"stream":true}`)

	ledger := &Ledger{byProvider: make(map[string]int)}
	for i := 1; i <= *n; i++ {
		fmt.Printf("\n=== request %d/%d ===\n", i, *n)
		spec, err := buildSpec(*provider, *host, *model, *query, body)
		if err != nil {
			logf("build spec: %v", err)
			continue
		}
		if err := runOnce(*teeURL, spec, body, *provider, *drop == i, ledger); err != nil {
			logf("request: %v", err)
		}
	}
	ledger.Print()
}

// Ledger accumulates the provider's view of usage and revenue.
type Ledger struct {
	requests   int
	verified   int
	revenue    float64
	byProvider map[string]int
}

func (l *Ledger) Print() {
	fmt.Printf("\n--- ledger ---\n")
	fmt.Printf("requests dispatched : %d\n", l.requests)
	fmt.Printf("receipts verified  : %d\n", l.verified)
	fmt.Printf("provider revenue   : %.2f units (price is provider-owned)\n", l.revenue)
	for p, c := range l.byProvider {
		fmt.Printf("  %s : %d completions\n", p, c)
	}
}

func buildSpec(provider, host, model, query string, body []byte) (jobs.Spec, error) {
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
		Path:             "/v1/chat/completions",
		Query:            query,
		Headers:          map[string]string{"Content-Type": "application/json"},
		BodyHash:         hashBodyBytes(body),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: 1 << 20,
		Stream:           true,
		DeclaredModel:    model,
		TenantRef:        []byte("tenant-demo-001"),
	}, nil
}

func runOnce(teeURL string, spec jobs.Spec, body []byte, provider string, withhold bool, ledger *Ledger) error {
	ledger.requests++
	reqBytes, err := shared.ExecuteRequest{Spec: spec, Body: body}.EncodeCanonical()
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	httpReq, err := httpPost(teeURL+"/v1/execute", "application/cbor", reqBytes)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call tee: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tee refused: %d %s", resp.StatusCode, string(b))
	}

	// --- Parse the SSE stream: forward chunks, capture the receipt frame.
	reader := bufio.NewReader(resp.Body)
	var eventType, data string
	var chunks [][]byte
	var receiptB64 string
	var gotError string
	flush := func() {
		switch eventType {
		case "", "message":
			if data != "" {
				fmt.Printf("[user sees] %s\n", data)
				chunks = append(chunks, []byte(data))
			}
		case "receipt":
			receiptB64 = data
		case "error":
			gotError = data
			fmt.Printf("[tee error] %s\n", data)
		}
		eventType, data = "", ""
	}
	for {
		line, rerr := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			flush()
			if rerr != nil {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
		} else if strings.HasPrefix(trimmed, "data:") {
			d := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			if data != "" {
				data += "\n"
			}
			data += d
		}
		if rerr != nil {
			if trimmed == "" {
				flush()
			}
			break
		}
	}

	if receiptB64 == "" {
		return fmt.Errorf("no receipt frame received (error: %s)", gotError)
	}

	signed, err := decodeReceipt(receiptB64)
	if err != nil {
		return fmt.Errorf("decode receipt: %w", err)
	}

	if err := proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}}); err != nil {
		return fmt.Errorf("verify receipt: %w", err)
	}
	ledger.verified++

	// The Hub can check the receipt's stream hash against the bytes it actually
	// forwarded — proving the TEE attested exactly this transcript.
	if !signed.Receipt.MatchesStream(chunks) {
		return fmt.Errorf("stream hash mismatch: TEE attested different bytes than forwarded")
	}

	r := signed.Receipt
	fmt.Printf("[receipt] provider=%s seq=%d requestBytes=%d responseBytes=%d chunks=%d status=%d completion=%s\n",
		r.Provider, r.ProviderSeq, r.RequestBytes, r.ResponseBytes, r.ChunkCount, r.StatusCode, r.Completion)

	// Pricing authority is the provider's: the Hub applies the provider's rate.
	if r.Completion == proof.CompletionComplete {
		ledger.revenue += pricePerRequest[provider]
		ledger.byProvider[provider]++
	}

	if withhold {
		fmt.Printf("[withhold] simulating Hub hiding seq=%d from provider\n", r.ProviderSeq)
		return nil
	}
	return writeReceiptToStore(provider, signed)
}

func runAudit(provider string) {
	dir := filepath.Join(shared.ConfigDir(), "receipts", provider)
	files, err := filepath.Glob(filepath.Join(dir, "*.cbor"))
	if err != nil || len(files) == 0 {
		fmt.Printf("no receipts stored for provider %q (dir=%s)\n", provider, dir)
		return
	}

	seqs := make([]uint64, 0, len(files))
	ok := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("  [BAD] %s: read: %v\n", filepath.Base(f), err)
			continue
		}
		var signed proof.SignedReceipt
		if err := canonical.Unmarshal(b, &signed); err != nil {
			fmt.Printf("  [BAD] %s: decode: %v\n", filepath.Base(f), err)
			continue
		}
		if err := proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}}); err != nil {
			fmt.Printf("  [BAD] %s: verify: %v\n", filepath.Base(f), err)
			continue
		}
		id, idErr := signed.Receipt.Identity()
		if idErr != nil {
			fmt.Printf("  [WARN] %s: identity: %v\n", filepath.Base(f), idErr)
		} else if err := simulated.CheckEvidence(id); err != nil {
			fmt.Printf("  [WARN] %s: evidence: %v\n", filepath.Base(f), err)
		}
		ok++
		seqs = append(seqs, signed.Receipt.ProviderSeq)
	}

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	fmt.Printf("verified %d/%d receipts for provider %q\n", ok, len(files), provider)

	// Gap detection: the whole point of ProviderSeq. A missing number means the
	// provider was used more times than the receipts it holds prove.
	maxSeq := uint64(0)
	for _, s := range seqs {
		if s > maxSeq {
			maxSeq = s
		}
	}
	seen := make(map[uint64]bool, len(seqs))
	for _, s := range seqs {
		seen[s] = true
	}
	var gaps []uint64
	for i := uint64(1); i <= maxSeq; i++ {
		if !seen[i] {
			gaps = append(gaps, i)
		}
	}
	if len(gaps) == 0 {
		fmt.Printf("sequence complete: 1..%d, no gaps\n", maxSeq)
	} else {
		fmt.Printf(">>> GAP DETECTED: provider was used at least %d times but is missing receipts %v\n", maxSeq, gaps)
	}
}

func decodeReceipt(b64 string) (proof.SignedReceipt, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return proof.SignedReceipt{}, err
	}
	var signed proof.SignedReceipt
	if err := canonical.Unmarshal(raw, &signed); err != nil {
		return proof.SignedReceipt{}, err
	}
	return signed, nil
}

func writeReceiptToStore(provider string, signed proof.SignedReceipt) error {
	dir := filepath.Join(shared.ConfigDir(), "receipts", provider)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	enc, err := signed.EncodeCanonical()
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d.cbor", signed.Receipt.ProviderSeq)
	return os.WriteFile(filepath.Join(dir, name), enc, 0o644)
}

func httpPost(url, contentType string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

func hashBodyBytes(body []byte) []byte {
	h := jobs.HashBody(body)
	return h[:]
}

func logf(format string, args ...any) { fmt.Printf("[hub] "+format+"\n", args...) }
