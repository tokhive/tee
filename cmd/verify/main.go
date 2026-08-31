// Command verify is the offline verifier a provider (or auditor) would run
// against the receipt store. It cryptographically verifies every stored
// SignedReceipt using the real proof.Verify path and the simulated platform's
// trust root, then reports any ProviderSeq gaps — the signal that the set of
// receipts is incomplete.
//
// Usage:
//   verify                       verify the whole store (.sim/receipts)
//   verify -provider openai-sim  verify one provider only
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
)

func main() {
	provider := flag.String("provider", "", "verify only this provider")
	flag.Parse()

	root := filepath.Join(shared.ConfigDir(), "receipts")
	providers := []string{*provider}
	if *provider == "" {
		entries, err := os.ReadDir(root)
		if err != nil {
			fmt.Printf("no receipt store at %s: %v\n", root, err)
			os.Exit(1)
		}
		providers = providers[:0]
		for _, e := range entries {
			if e.IsDir() {
				providers = append(providers, e.Name())
			}
		}
	}

	overallBad := false
	for _, p := range providers {
		if bad := auditProvider(p, filepath.Join(root, p)); bad {
			overallBad = true
		}
	}
	if overallBad {
		os.Exit(1)
	}
}

func auditProvider(provider, dir string) bool {
	files, err := filepath.Glob(filepath.Join(dir, "*.cbor"))
	if err != nil || len(files) == 0 {
		fmt.Printf("[%s] no receipts\n", provider)
		return false
	}

	seqs := make([]uint64, 0, len(files))
	bad := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("  [BAD] %s: %v\n", filepath.Base(f), err)
			bad++
			continue
		}
		var signed proof.SignedReceipt
		if err := canonical.Unmarshal(b, &signed); err != nil {
			fmt.Printf("  [BAD] %s: decode: %v\n", filepath.Base(f), err)
			bad++
			continue
		}
		if err := proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}}); err != nil {
			fmt.Printf("  [BAD] %s: verify: %v\n", filepath.Base(f), err)
			bad++
			continue
		}
		seqs = append(seqs, signed.Receipt.ProviderSeq)
	}

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if len(seqs) == 0 {
		return bad > 0
	}

	maxSeq := seqs[len(seqs)-1]
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
		fmt.Printf("[%s] OK: %d receipts, sequence 1..%d complete\n", provider, len(seqs), maxSeq)
		return bad > 0
	}
	fmt.Printf("[%s] GAP: %d receipts but missing seq %v (provider used at least %d times)\n",
		provider, len(seqs), gaps, maxSeq)
	return true
}
