// Package canonical provides the deterministic CBOR encoding used by every
// TokenHive structure that ends up inside a hash or a signature.
//
// All TokenHive digests and signatures are computed over canonical bytes, so a
// byte-identical structure must always produce a byte-identical encoding. The
// encoding follows RFC 8949 section 4.2.1 (core deterministic encoding):
//
//   - integers and lengths use the shortest possible form
//   - map keys are sorted by their encoded bytes
//   - indefinite-length items are never produced
//
// Structs are expected to use integer map keys (`cbor:"1,keyasint"`) rather than
// field names. Integer keys keep receipts compact — the roadmap caps an
// attestation-bearing receipt at 2KB — and make key ordering independent of any
// future field rename.
package canonical

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNonCanonical means decoded bytes were not produced by this encoder and
// must be rejected before any hash or signature is trusted.
var ErrNonCanonical = errors.New("CBOR input is not in canonical form")

// Encoder is the deterministic encoding mode shared by the TokenHive packages.
var Encoder cbor.EncMode

func init() {
	options := cbor.CanonicalEncOptions()
	options.Sort = cbor.SortCanonical

	mode, err := options.EncMode()
	if err != nil {
		panic(fmt.Sprintf("canonical: build CBOR encoding mode: %v", err))
	}
	Encoder = mode
}

// Marshal encodes value deterministically.
func Marshal(value any) ([]byte, error) {
	encoded, err := Encoder.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical: encode: %w", err)
	}
	return encoded, nil
}

// Unmarshal decodes a structure that was produced by Marshal. It rejects any
// input that would not re-encode to the exact same bytes, which blocks
// signature-level malleability from duplicate keys or non-shortest lengths.
func Unmarshal(data []byte, value any) error {
	decoder, err := cbor.DecOptions{
		// Duplicate keys are a classic way to make two encodings of the same
		// logical object; the canonical re-encode check below catches what
		// slips through, but rejecting up front gives a better error.
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		return fmt.Errorf("canonical: build decoding mode: %w", err)
	}
	if err := decoder.Unmarshal(data, value); err != nil {
		return fmt.Errorf("canonical: decode: %w", err)
	}

	reencoded, err := Marshal(value)
	if err != nil {
		return fmt.Errorf("canonical: re-encode: %w", err)
	}
	if !bytes.Equal(reencoded, data) {
		return ErrNonCanonical
	}
	return nil
}
