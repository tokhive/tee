// Package evidence is a small, restart-surviving attestation evidence store.
//
// A TEE signs receipts on an RA-TLS key epoch; those receipts carry either the
// full attestation evidence inline or a short EvidenceHash that a verifier must
// resolve against evidence it saw when the TEE came online. Inline evidence is
// self-contained but costs several kilobytes per receipt, so a deployment that
// ships the small hash-only receipt form needs somewhere durable to look the
// bytes up.
//
// This package is that somewhere. The TEE writes its current epoch's evidence
// here (by evidence hash) on every sign/key rotation; a verifier — an offline
// auditor, a Hub, a provider — points a Fetcher at the same store and resolves
// the hash. Because the store is keyed by the SHA-256 of the evidence itself,
// and a verifier refuses bytes whose hash does not match, an old or rotated
// epoch keeps resolving to the exact evidence the TEE once presented: evidence
// retrieved is evidence the store guarantees is authentic under the hash the
// receipt names.
//
// The store is append-only by design: entries are added as the TEE rotates, and
// never removed, so a receipt is verifiable for as long as the deployment keeps
// its evidence history.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Store persists attestation evidence keyed by its SHA-256 hash. The key is
// the hash of the evidence itself, so the store is a self-validating cache of
// "evidence the deployment has seen a TEE present".
type Store struct {
	dir string
}

// NewStore opens (creating if needed) an evidence store rooted at dir.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("evidence: empty store directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence: create store %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// evidenceName keys one entry. The file name is the hex of the evidence hash;
// the file stores the raw evidence bytes. Two identities with the same evidence
// hash resolve to the same file, which is correct — identical bytes are the
// same evidence under any key.
func (s *Store) evidenceName(id platform.Identity) string {
	return hex.EncodeToString(id.EvidenceHash[:]) + ".bin"
}

// Put records the identity's full evidence. Empty evidence is ignored; the
// store only ever holds bytes it can be asked to resolve.
func (s *Store) Put(id platform.Identity) error {
	if len(id.Evidence) == 0 {
		return nil
	}
	if sum := sha256.Sum256(id.Evidence); sum != id.EvidenceHash {
		return errors.New("evidence: identity evidence does not match its hash")
	}
	path := filepath.Join(s.dir, s.evidenceName(id))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, id.Evidence, 0o644); err != nil {
		return fmt.Errorf("evidence: write %s: %w", path, err)
	}
	// Write-then-rename so a crash cannot leave a truncated entry that later
	// fails its hash and looks like the deployment lost evidence.
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("evidence: finalize %s: %w", path, err)
	}
	return nil
}

// ErrNoEvidence means the store has no bytes matching the request.
var ErrNoEvidence = errors.New("evidence: not found")

// Load returns the stored evidence for id, verifying that its SHA-256 matches
// the hash the caller names. A mismatch is a store-corruption error, never a
// silent wrong answer.
func (s *Store) Load(id platform.Identity) ([]byte, error) {
	path := filepath.Join(s.dir, s.evidenceName(id))
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoEvidence
		}
		return nil, fmt.Errorf("evidence: read %s: %w", path, err)
	}
	if sum := sha256.Sum256(b); sum != id.EvidenceHash {
		return nil, fmt.Errorf("evidence: stored bytes for %x do not match the evidence hash", id.EvidenceHash)
	}
	return b, nil
}

// Fetch implements attest.Fetcher by resolving hash-only identities in the
// store. It is the offline half of the evidence-retrieval story.
func (s *Store) Fetch(_ context.Context, id platform.Identity) ([]byte, error) {
	return s.Load(id)
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Has reports whether an entry is present for a hash (without reading it).
func (s *Store) Has(id platform.Identity) bool {
	_, err := os.Stat(filepath.Join(s.dir, s.evidenceName(id)))
	return err == nil
}

// ListHashes returns the hex evidence hashes currently stored, sorted. It is
// how a migrating verifier syncs its cache from a peer's store.
func (s *Store) ListHashes() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("evidence: list store: %w", err)
	}
	var hashes []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		hashes = append(hashes, strings.TrimSuffix(e.Name(), ".bin"))
	}
	return hashes, nil
}
