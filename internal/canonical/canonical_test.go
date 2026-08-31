package canonical

import (
	"errors"
	"testing"
)

// TestUnmarshalRejectsUnsortedKeys is the malleability guard. Two encodings of
// the same logical map must not both be accepted: if they were, an attacker
// could reserialize a signed structure and change the bytes without changing
// the meaning, breaking any system that hashes or indexes those bytes.
func TestUnmarshalRejectsUnsortedKeys(t *testing.T) {
	// map(2): {2: 2, 1: 1} — keys out of canonical order.
	unsorted := []byte{0xA2, 0x02, 0x02, 0x01, 0x01}
	var target map[uint64]uint64

	err := Unmarshal(unsorted, &target)
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("got %v, want %v", err, ErrNonCanonical)
	}

	// map(2): {1: 1, 2: 2} — the canonical spelling of the same map.
	sorted := []byte{0xA2, 0x01, 0x01, 0x02, 0x02}
	target = nil
	if err := Unmarshal(sorted, &target); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	if target[1] != 1 || target[2] != 2 {
		t.Fatalf("decoded %v, want map[1:1 2:2]", target)
	}
}

// TestUnmarshalRejectsNonShortestIntegers covers the other half of RFC 8949
// deterministic encoding: a value must use the shortest form that fits.
func TestUnmarshalRejectsNonShortestIntegers(t *testing.T) {
	// map(1): {1: 1} where the value is encoded as a 1-byte integer (0x18 0x01)
	// instead of the small integer form (0x01).
	inflated := []byte{0xA1, 0x01, 0x18, 0x01}
	var target map[uint64]uint64

	err := Unmarshal(inflated, &target)
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("got %v, want %v", err, ErrNonCanonical)
	}
}

func TestRoundTrip(t *testing.T) {
	type sample struct {
		Name  string `cbor:"1,keyasint"`
		Count uint64 `cbor:"2,keyasint"`
		Blob  []byte `cbor:"3,keyasint,omitempty"`
	}

	original := sample{Name: "tokenhive", Count: 42, Blob: []byte{0x01, 0x02}}
	encoded, err := Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded sample
	if err := Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Name != original.Name || decoded.Count != original.Count {
		t.Fatalf("round trip mismatch: got %+v, want %+v", decoded, original)
	}
}
