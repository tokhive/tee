// Command faketee is the in-memory A-layer TEE used for fast Hub business
// tests. Like cmd/tee it runs the REAL tee.Service, but instead of dialing a
// provider it answers with a fixed, deterministic SSE stream. No network and
// no real credential egress are involved, so the Hub's pricing, ledger, and
// ProviderSeq gap-detection logic can iterate in milliseconds.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// mockChunks is the fixed, deterministic response stream. Because it never
// changes, the TEE's StreamHash is stable and the Hub can make golden
// assertions against it.
var mockChunks = []string{
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"你好"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"，我是由 TokenHive 托管的"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"模拟模型，不调用任何真实大模型。"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]}`,
}

// scriptedTransport is an in-memory tee.Transport returning a fixed SSE stream.
// It lets the A-layer fake exercise the real tee.Service without a provider.
//
// To mirror the real HTTP transport's contract exactly, non-2xx "fault" codes
// are surfaced as a status code with a NIL error (the exchange completed; the
// provider simply said no), and a mid-stream disconnect is surfaced as a
// non-EOF error — which is what makes the TEE attest CompletionTruncated
// rather than CompletionFailed. This keeps the simulated path faithful to the
// genuine one so the Hub-side logic is tested against real semantics.
type scriptedTransport struct{}

func (scriptedTransport) Do(ctx context.Context, req tee.Request, onChunk func([]byte) error) (tee.Response, error) {
	fault := queryParam(req.Query, "fault")

	// Provider returned an error status. Like the real transport, this is NOT
	// an error from the exchange's point of view — the bytes arrived, the
	// provider just declined. The receipt records the status code.
	switch fault {
	case "401":
		return tee.Response{StatusCode: 401}, nil
	case "429":
		return tee.Response{StatusCode: 429}, nil
	}

	emit := func() error {
		for _, c := range mockChunks {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := onChunk([]byte(c)); err != nil {
				return err
			}
		}
		return nil
	}

	// Normal completion.
	if fault != "truncate" {
		if err := emit(); err != nil {
			return tee.Response{StatusCode: 200}, err
		}
		return tee.Response{StatusCode: 200}, nil
	}

	// Mid-stream disconnect: relay the first two chunks, then fail the
	// connection the way a dropped provider socket would. The TEE attests the
	// partial transcript as CompletionTruncated.
	for i, c := range mockChunks {
		if i == 2 {
			break
		}
		if err := onChunk([]byte(c)); err != nil {
			return tee.Response{StatusCode: 200}, err
		}
	}
	return tee.Response{StatusCode: 200}, errors.New("simulated provider dropped the connection mid-stream")
}

// queryParam fetches the value of a single key from an already-escaped query
// string (e.g. "fault=401&other=x"). It mirrors how the real transport hands
// the spec's raw query to the provider URL untouched.
func queryParam(query, key string) string {
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		name, val, hasVal := strings.Cut(kv, "=")
		if name == key {
			if hasVal {
				return val
			}
			return ""
		}
	}
	return ""
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "listen address")
	seqPath := flag.String("seq", "", "ProviderSeq store file (default <simdir>/seqstore.json)")
	flag.Parse()

	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	policies, err := shared.LoadPolicySetAll()
	if err != nil {
		log.Fatalf("load policy set: %v", err)
	}
	policySetHash, err := policies.Hash()
	if err != nil {
		log.Fatalf("hash policy set: %v", err)
	}

	// Like the real TEE, the A-layer fake binds its loaded whitelist into the
	// simulated attestation evidence, so receipts it produces are comparable
	// to the real TEE's.
	epoch, err := simulated.NewDeploymentEpoch(policySetHash)
	if err != nil {
		log.Fatalf("create sim epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
	}

	// The A-layer fake never egresses: its transport answers with canned bytes,
	// so the execution path only needs to decrypt a job's envelope. Like the real
	// TEE it stores no credential — it holds an inbox key, and each job brings its
	// provider's token sealed to it. The credential-key endpoint is served so the
	// agent-registration/one-shot sealing path can be exercised end to end.
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		log.Fatalf("generate inbox key: %v", err)
	}

	signer := proof.NewSigner(epoch)
	// Self-contained receipts so the offline verifier needs no external
	// attestation cache (see plan P0).
	signer.IncludeEvidence = true

	if *seqPath == "" {
		*seqPath = filepath.Join(shared.ConfigDir(), "seqstore.json")
	}
	store, err := tee.NewFileSeqStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	svc, err := tee.NewService(tee.Config{
		Policies:  policies,
		Transport: scriptedTransport{},
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
	// Credential plane, mirroring cmd/tee: agents (or one-shot tools) fetch the
	// inbox key, seal their token to it, and present the envelope on each job.
	mux.HandleFunc("/v1/credential-key", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeCredentialKey(inbox, w, r)
	})
	log.Printf("faketee (in-memory A-layer TEE, real service) listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
