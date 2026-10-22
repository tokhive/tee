//go:build !mobile

package shared

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const fakeSAToken = "fake-token"

func stubTokens(_ context.Context, _ string) (string, error) {
	return fakeSAToken, nil
}

// TestRouterClient_Register_HappyPath verifies that Register POSTs to the
// right path with the bearer token attached, parses the response, and that
// the token source receives the router URL as the audience (which is what
// the router validates against).
func TestRouterClient_Register_HappyPath(t *testing.T) {
	var seenPath, seenAuth string
	var seenBody RegisterRequest
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seenBody)
		_ = json.MarshalWrite(w, RegisterResponse{
			PairID: seenBody.PairID, Status: "registering",
		})
	}))
	httpClient := srv.Client()

	var seenAudience string
	tokens := func(_ context.Context, aud string) (string, error) {
		seenAudience = aud
		return fakeSAToken, nil
	}
	c := NewRouterClient(srv.URL, tokens)
	c.httpClient = httpClient
	_, err := c.Register(t.Context(), RegisterRequest{
		PairID: "p1", Role: "K", SelfAddr: "10.0.0.1:443",
		PeerAddrClaim: "10.0.0.2:443", ImageDigest: "sha256:abc",
		AttestationJWT: "att-blob",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if seenAudience != srv.URL {
		t.Fatalf("token source got audience %q, want %q", seenAudience, srv.URL)
	}
	if seenPath != "/register" {
		t.Fatalf("path: %q", seenPath)
	}
	if seenAuth != "Bearer "+fakeSAToken {
		t.Fatalf("auth header: %q", seenAuth)
	}
	if seenBody.PairID != "p1" || seenBody.Role != "K" {
		t.Fatalf("body: %+v", seenBody)
	}
}

// TestRouterClient_Heartbeat_404IsErrNotFound — if the router doesn't know
// the pair_id (e.g. router restart wiped in-memory state), heartbeat must
// surface ErrRouterNotFound so the TEE can decide to re-register.
func TestRouterClient_Heartbeat_404IsErrNotFound(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "pair not found", http.StatusNotFound)
	}))
	httpClient := srv.Client()

	c := NewRouterClient(srv.URL, stubTokens)
	c.httpClient = httpClient
	_, err := c.Heartbeat(t.Context(), HeartbeatRequest{PairID: "p1", Role: "K"})
	if !errors.Is(err, ErrRouterNotFound) {
		t.Fatalf("expected ErrRouterNotFound, got %v", err)
	}
}

func TestRouterClient_BaseURLTrailingSlash(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			t.Errorf("expected /register, got %q (should not get doubled slashes)", r.URL.Path)
		}
		_ = json.MarshalWrite(w, RegisterResponse{PairID: "p1", Status: "registering"})
	}))
	httpClient := srv.Client()

	c := NewRouterClient(srv.URL+"/", stubTokens)
	c.httpClient = httpClient
	if _, err := c.Register(t.Context(), RegisterRequest{
		PairID: "p1", Role: "K", SelfAddr: "x", PeerAddrClaim: "y",
		ImageDigest: "z", AttestationJWT: "a",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
}

func TestRouterClient_TokenError(t *testing.T) {
	c := NewRouterClient("http://unused", func(_ context.Context, _ string) (string, error) {
		return "", errors.New("metadata unreachable")
	})
	_, err := c.Register(t.Context(), RegisterRequest{
		PairID: "p1", Role: "K", SelfAddr: "x", PeerAddrClaim: "y",
		ImageDigest: "z", AttestationJWT: "a",
	})
	if err == nil {
		t.Fatal("expected error from token source")
	}
}

// TestRouterClient_500ReturnsError confirms that non-2xx is propagated.
func TestRouterClient_500ReturnsError(t *testing.T) {
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	httpClient := srv.Client()

	c := NewRouterClient(srv.URL, stubTokens)
	c.httpClient = httpClient
	_, err := c.Register(t.Context(), RegisterRequest{
		PairID: "p1", Role: "K", SelfAddr: "x", PeerAddrClaim: "y",
		ImageDigest: "z", AttestationJWT: "a",
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
}
