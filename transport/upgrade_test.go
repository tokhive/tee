package transport

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tokhive/tee/tee"
)

// TestAcceptKeyMatchesTheRFCExample pins the accept computation against the
// example in RFC 6455 §1.3. A verifier that disagrees with the RFC would
// reject every real provider, so this is the one vector worth hard-coding.
func TestAcceptKeyMatchesTheRFCExample(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := acceptKey(key); got != want {
		t.Fatalf("acceptKey(%q) = %q, want %q", key, got, want)
	}
}

func upgradeResponse(key string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Upgrade":    []string{"websocket"},
			"Connection": []string{"Upgrade"},
			"Sec-Websocket-Accept": []string{
				acceptKey(key),
			},
			"Sec-Websocket-Protocol": []string{"realtime"},
		},
	}
}

func TestVerifyUpgradeResponseAcceptsAValidHandshake(t *testing.T) {
	proto, err := verifyUpgradeResponse(upgradeResponse("key"), "key")
	if err != nil {
		t.Fatalf("valid handshake refused: %v", err)
	}
	if proto != "realtime" {
		t.Fatalf("subprotocol = %q, want realtime", proto)
	}
}

func TestVerifyUpgradeResponseRejectsAWrongAccept(t *testing.T) {
	resp := upgradeResponse("key")
	resp.Header.Set("Sec-Websocket-Accept", acceptKey("another key"))
	if _, err := verifyUpgradeResponse(resp, "key"); err == nil {
		t.Fatal("a 101 without the accept value for our key was accepted")
	}
}

func TestVerifyUpgradeResponseRejectsAMissingUpgradeToken(t *testing.T) {
	resp := upgradeResponse("key")
	resp.Header.Del("Upgrade")
	if _, err := verifyUpgradeResponse(resp, "key"); err == nil {
		t.Fatal("a 101 without Upgrade: websocket was accepted")
	}
}

func TestVerifyUpgradeResponseRejectsNegotiatedExtensions(t *testing.T) {
	resp := upgradeResponse("key")
	resp.Header.Set("Sec-Websocket-Extensions", "permessage-deflate")
	if _, err := verifyUpgradeResponse(resp, "key"); err == nil {
		t.Fatal("an extension the TEE never offered was accepted")
	}
}

func TestVerifyUpgradeResponseRejectsANon101(t *testing.T) {
	resp := upgradeResponse("key")
	resp.StatusCode = http.StatusOK
	if _, err := verifyUpgradeResponse(resp, "key"); err == nil {
		t.Fatal("a 200 response was accepted as an upgrade")
	}
}

// TestBuildUpgradeBytesKeepsCallerHeadersButNotHandshakeOnes pins the split
// between what the TEE states itself and what the spec may add. A caller cannot
// override the key whose accept value is verified, but it can still carry the
// Origin and subprotocol headers a provider needs.
func TestBuildUpgradeBytesKeepsCallerHeadersButNotHandshakeOnes(t *testing.T) {
	req := tee.Request{
		Method: "GET",
		Host:   "api.example.com",
		Path:   "/v1/realtime",
		Query:  "model=x",
		Headers: map[string]string{
			"Origin":                   "https://example.com",
			"Sec-WebSocket-Protocol":   "realtime",
			"Sec-WebSocket-Key":        "caller-key",
			"Sec-WebSocket-Version":    "99",
			"Sec-WebSocket-Extensions": "permessage-deflate",
			"Authorization":            "Bearer token",
		},
	}
	raw, err := buildUpgradeBytes(req, "verified-key")
	if err != nil {
		t.Fatalf("buildUpgradeBytes: %v", err)
	}
	wire := string(raw)
	for _, want := range []string{
		"GET /v1/realtime?model=x HTTP/1.1\r\n",
		"Host: api.example.com\r\n",
		"Sec-WebSocket-Key: verified-key\r\n",
		"Origin: https://example.com\r\n",
		"Sec-WebSocket-Protocol: realtime\r\n",
		"Authorization: Bearer token\r\n",
	} {
		if !strings.Contains(wire, want) {
			t.Fatalf("upgrade request missing %q:\n%s", want, wire)
		}
	}
	for _, unwanted := range []string{"caller-key", "Version: 99", "permessage-deflate"} {
		if strings.Contains(wire, unwanted) {
			t.Fatalf("upgrade request carries a header the TEE must state itself (%q):\n%s", unwanted, wire)
		}
	}
	if got := strings.Count(wire, "Sec-WebSocket-Key:"); got != 1 {
		t.Fatalf("Sec-WebSocket-Key appears %d times, want exactly once", got)
	}
}

// A handshake has no body, so a caller-supplied framing header can only be a
// second framing the provider did not agree to. It is dropped with the rest of
// what the TEE owns.
func TestBuildUpgradeBytesDropsFramingHeaders(t *testing.T) {
	req := tee.Request{
		Method: "GET",
		Host:   "api.example.com",
		Path:   "/v1/realtime",
		Headers: map[string]string{
			"Content-Length":      "99",
			"Transfer-Encoding":   "chunked",
			"Keep-Alive":          "timeout=5",
			"Proxy-Authorization": "Basic caller",
			"X-Custom":            "kept",
		},
	}
	raw, err := buildUpgradeBytes(req, "verified-key")
	if err != nil {
		t.Fatalf("buildUpgradeBytes: %v", err)
	}
	wire := string(raw)
	for _, unwanted := range []string{"Content-Length", "Transfer-Encoding", "Keep-Alive", "Proxy-Authorization"} {
		if strings.Contains(wire, unwanted) {
			t.Fatalf("handshake carries %q, which the TEE must not copy:\n%s", unwanted, wire)
		}
	}
	if !strings.Contains(wire, "X-Custom: kept\r\n") {
		t.Fatalf("caller header dropped:\n%s", wire)
	}
}

// The request line is rendered from fields the TEE owns, so a line break or a
// space in any of them is refused instead of splitting what the receipt says
// from what goes on the wire.
func TestBuildRequestRejectsLineBreaks(t *testing.T) {
	cases := map[string]tee.Request{
		"method": {Method: "GET\r\nX-Injected: 1", Host: "api.example.com", Path: "/"},
		"host":   {Method: "GET", Host: "api.example.com\r\nX-Injected: 1", Path: "/"},
		"path":   {Method: "GET", Host: "api.example.com", Path: "/v1\r\nX-Injected: 1"},
		"query":  {Method: "GET", Host: "api.example.com", Path: "/v1", Query: "a=1\r\nX-Injected: 1"},
		"space":  {Method: "GET", Host: "api.example.com", Path: "/v1 a"},
	}
	for name, req := range cases {
		if _, err := buildRequestHead(req); err == nil {
			t.Errorf("%s: buildRequestHead accepted a line break", name)
		}
		if _, err := buildUpgradeBytes(req, "verified-key"); err == nil {
			t.Errorf("%s: buildUpgradeBytes accepted a line break", name)
		}
	}
}
