package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/tokhive/tee/policy"
)

func TestReportsTheReceiptPolicyHashForTheActualBytes(t *testing.T) {
	p, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	p.Hosts = []string{"custom.example"}
	raw, err := p.EncodeCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := p.Hash()
	fileHash := sha256.Sum256(raw)
	var out, errOut bytes.Buffer
	if code := run([]string{"-"}, bytes.NewReader(raw), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	var info policyInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Hash != hex.EncodeToString(want[:]) || info.FileSHA256 != hex.EncodeToString(fileHash[:]) || info.Hash == info.FileSHA256 {
		t.Fatalf("policy hash must use policy.Hash, with the raw-file digest separate: %+v", info)
	}
}

func TestRejectsMalformedNonCanonicalAndInvalidPolicies(t *testing.T) {
	p, _ := policy.Default()
	raw, _ := p.EncodeCanonical()
	// A deliberately overlong map-length encoding must not be accepted.
	nonCanonical := append([]byte{0xb8, raw[0] & 0x1f}, raw[1:]...)
	p.Hosts = nil
	invalid, _ := p.EncodeCanonical()
	for _, input := range [][]byte{[]byte("bad CBOR"), nonCanonical, invalid, make([]byte, (2<<20)+1)} {
		var out, errOut bytes.Buffer
		if code := run([]string{"-"}, bytes.NewReader(input), &out, &errOut); code != 1 || out.Len() != 0 {
			t.Fatalf("invalid policy accepted: code=%d output=%s", code, &out)
		}
	}
}

func TestCanEmitTheDefaultCanonicalPolicy(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--emit-default"}, nil, &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	if _, err := inspect(out.Bytes()); err != nil {
		t.Fatal(err)
	}
}
