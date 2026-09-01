package hub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// ErrDuplicateSeq means a receipt arrived carrying a ProviderSeq the store
// already holds. The sequence is monotonic per provider, so a repeat means one
// of two things: the Hub is replaying, or two TEEs are minting numbers from
// the same counter. Both deserve to be loud rather than quietly overwritten.
var ErrDuplicateSeq = errors.New("receipt sequence already stored")

// Store persists the receipts a provider is entitled to audit.
//
// Deliberately narrow: the Hub's only obligation is to hand receipts over.
// Auditing them is the provider's job and needs more than Put.
type Store interface {
	Put(provider string, signed proof.SignedReceipt) error
}

// ReceiptStore keeps one canonical-CBOR file per receipt, named after the
// ProviderSeq it carries.
//
// It is the artifact a provider would pull to check the Hub's honesty, so it
// is kept in the provider's own directory and named by sequence rather than by
// anything the Hub chooses — the numbering is the thing under audit.
type ReceiptStore struct {
	dir string
}

// NewReceiptStore returns a store rooted at dir.
func NewReceiptStore(dir string) *ReceiptStore {
	return &ReceiptStore{dir: dir}
}

// Put writes a receipt for a provider, refusing to overwrite one already held.
func (s *ReceiptStore) Put(provider string, signed proof.SignedReceipt) error {
	if err := jobs.ValidateProviderName(provider); err != nil {
		return fmt.Errorf("invalid provider: %w", err)
	}
	enc, err := signed.EncodeCanonical()
	if err != nil {
		return fmt.Errorf("encode receipt: %w", err)
	}
	dir := s.dirFor(provider)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.cbor", signed.Receipt.ProviderSeq))
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %s already holds seq %d",
			ErrDuplicateSeq, provider, signed.Receipt.ProviderSeq)
	}
	// Write-then-rename so a crash cannot leave a truncated receipt that later
	// fails to decode and reads as a gap the provider cannot explain.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// List returns every stored receipt for a provider, ordered by ProviderSeq.
func (s *ReceiptStore) List(provider string) ([]proof.SignedReceipt, error) {
	files, err := s.files(provider)
	if err != nil {
		return nil, err
	}
	receipts := make([]proof.SignedReceipt, 0, len(files))
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var signed proof.SignedReceipt
		if err := canonical.Unmarshal(b, &signed); err != nil {
			return nil, fmt.Errorf("decode %s: %w", filepath.Base(path), err)
		}
		receipts = append(receipts, signed)
	}
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].Receipt.ProviderSeq < receipts[j].Receipt.ProviderSeq
	})
	return receipts, nil
}

// AuditReport is the outcome of checking a provider's receipts.
type AuditReport struct {
	// Total is how many receipt files were found.
	Total int
	// Verified is how many passed signature and attestation checks.
	Verified int
	// Invalid is how many could not be decoded or did not verify.
	Invalid int
	// MaxSeq is the highest ProviderSeq seen. It is a lower bound on how many
	// times the provider's credential was used, and it is the number that
	// gives a gap its meaning.
	MaxSeq uint64
	// Missing lists the sequence numbers below MaxSeq with no receipt.
	Missing []uint64
}

// Complete reports whether the provider holds an unbroken run up to MaxSeq.
func (r AuditReport) Complete() bool { return len(r.Missing) == 0 }

// Audit verifies every stored receipt for a provider and reports gaps.
//
// This is the whole reason ProviderSeq exists. A signature proves one receipt
// is genuine; only the sequence says anything about the set. A provider that
// holds 1 and 3 knows it was used at least three times and can demand the
// record for 2 — the Hub cannot hide an execution without leaving a hole.
//
// Verify is required: auditing without checking signatures would tell a
// provider its books are complete on the Hub's word, which is the one thing
// this mechanism exists not to do.
func (s *ReceiptStore) Audit(provider string, verify func(proof.SignedReceipt) error) (AuditReport, error) {
	if verify == nil {
		return AuditReport{}, ErrNoVerifier
	}
	files, err := s.files(provider)
	if err != nil {
		return AuditReport{}, err
	}

	var report AuditReport
	seen := make(map[uint64]bool, len(files))
	for _, path := range files {
		report.Total++

		b, err := os.ReadFile(path)
		if err != nil {
			report.Invalid++
			continue
		}
		var signed proof.SignedReceipt
		if err := canonical.Unmarshal(b, &signed); err != nil {
			report.Invalid++
			continue
		}
		if err := verify(signed); err != nil {
			report.Invalid++
			continue
		}
		report.Verified++

		seq := signed.Receipt.ProviderSeq
		seen[seq] = true
		if seq > report.MaxSeq {
			report.MaxSeq = seq
		}
	}

	for seq := uint64(1); seq <= report.MaxSeq; seq++ {
		if !seen[seq] {
			report.Missing = append(report.Missing, seq)
		}
	}
	return report, nil
}

func (s *ReceiptStore) files(provider string) ([]string, error) {
	if err := jobs.ValidateProviderName(provider); err != nil {
		return nil, fmt.Errorf("invalid provider: %w", err)
	}
	files, err := filepath.Glob(filepath.Join(s.dirFor(provider), "*.cbor"))
	if err != nil {
		return nil, fmt.Errorf("list receipts: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func (s *ReceiptStore) dirFor(provider string) string {
	return filepath.Join(s.dir, provider)
}
