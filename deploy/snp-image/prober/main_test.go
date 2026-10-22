package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestGzipBytesRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte("firmware-event-log\x00"), 4096)
	got, err := gzipBytes(raw)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("gzip round trip changed event-log bytes")
	}
}
