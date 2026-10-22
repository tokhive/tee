//go:build !mobile

package shared

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RouterClient talks to the multi-pair router service from inside a TEE.
// All requests carry a GCP service-account identity token in
// Authorization: Bearer. The token is minted with the router's URL as its
// `aud` claim, which must match the SA_TOKEN_AUDIENCE the router validates
// against — operator's responsibility to keep these aligned at deploy time.
type RouterClient struct {
	baseURL    string
	httpClient *http.Client
	tokens     TokenSource
}

// TokenSource returns a fresh GCP SA identity token for the given audience.
// In production: queries http://metadata.google.internal/.../identity?audience=.
// In tests: a stub.
type TokenSource func(ctx context.Context, audience string) (string, error)

// NewRouterClient builds a client pointing at the router base URL (e.g.
// "https://tee.reclaimprotocol.org"). The same URL is used as the
// `aud` claim when minting SA identity tokens.
func NewRouterClient(baseURL string, tokens TokenSource) *RouterClient {
	return &RouterClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		tokens:     tokens,
	}
}

// RegisterRequest is the body of POST /register. SPKIDer + BodySignature
// bind the body to the attestation: the TEE signs RegistrationSigningDigest
// with the RA-TLS private key whose public half's hash is committed in the
// attestation (CS eat_nonce / SEV-SNP report_data). Empty in standalone mode.
type RegisterRequest struct {
	PairID          string `json:"pair_id"`
	Role            string `json:"role"`
	SelfAddr        string `json:"self_addr"`
	PeerAddrClaim   string `json:"peer_addr_claim"`
	ImageDigest     string `json:"image_digest"`
	AttestationType string `json:"attestation_type,omitempty"`
	AttestationJWT  string `json:"attestation_jwt"`
	SPKIDer         []byte `json:"spki_der,omitempty"`
	BodySignature   []byte `json:"body_signature,omitempty"`
}

// RegistrationSigningDigest is the message a TEE signs with its RA-TLS
// private key to prove a /register body came from the enclave whose
// attestation commits to that keypair. Domain-separated so the signature
// can't be replayed as any other kind of ECDSA signature by that key.
func RegistrationSigningDigest(pairID, role, selfAddr, peerAddrClaim, imageDigest string) [32]byte {
	h := sha256.New()
	h.Write([]byte("reclaim-register-binding-v1"))
	for _, f := range []string{pairID, role, selfAddr, peerAddrClaim, imageDigest} {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RegisterResponse is the body returned by /register.
type RegisterResponse struct {
	PairID string `json:"pair_id"`
	Status string `json:"status"`
}

// Register calls POST /register. The router's audience for SA-token
// validation is configured server-side; we pass the same value when we
// fetch our identity token so the token's aud claim matches.
func (c *RouterClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.postJSON(ctx, "/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HeartbeatRequest is the body of POST /heartbeat.
type HeartbeatRequest struct {
	PairID            string `json:"pair_id"`
	Role              string `json:"role"`
	ControlHealthy    bool   `json:"control_healthy"`
	OTReady           bool   `json:"ot_ready"`
	ActiveSessions    int    `json:"active_sessions"`
	LastPeerContactMS int64  `json:"last_peer_contact_ms"`
}

// HeartbeatResponse is the body returned by /heartbeat.
type HeartbeatResponse struct {
	PairID string `json:"pair_id"`
	Status string `json:"status"`
}

// Heartbeat calls POST /heartbeat. A 404 indicates the router has no record
// of this pair_id — the TEE should treat this as evidence that it needs to
// re-register (e.g. after a router restart in single-instance mode).
func (c *RouterClient) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.postJSON(ctx, "/heartbeat", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ErrRouterNotFound is returned when the router responds 404. The only
// router endpoint that currently returns 404 in normal operation is
// /heartbeat for an unknown pair_id, so callers can treat this as a signal
// to re-register (e.g. after a router restart in single-replica mode wiped
// in-memory state). Match with errors.Is.
var ErrRouterNotFound = errors.New("router: not found")

func (c *RouterClient) postJSON(ctx context.Context, path string, reqBody, respBody any) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	token, err := c.tokens(ctx, c.baseURL)
	if err != nil {
		return fmt.Errorf("get SA identity token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusNotFound {
		return ErrRouterNotFound
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("router %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	if respBody == nil {
		return nil
	}
	if err := json.Unmarshal(body, respBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// DiscoverGCEExternalIP returns the external (NAT) IP assigned to the
// first network interface of the current GCE VM, queried via the
// instance metadata server. Used by TEEs in router mode to fill in
// SELF_ADDR automatically — ephemeral IPs aren't known at create time,
// so the binary discovers its own at boot.
//
// Returns an error if the metadata server is unreachable (i.e. we're
// not running on GCE) or if the access-configs[0]/external-ip field is
// absent (instance has no external IP).
func DiscoverGCEExternalIP(ctx context.Context) (string, error) {
	const u = "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d: %s", resp.StatusCode, string(body))
	}
	ip := string(bytes.TrimSpace(body))
	if ip == "" {
		return "", errors.New("metadata server returned empty external IP (instance has no external NIC?)")
	}
	return ip, nil
}

// NoopTokenSource always returns an empty token. Use in local-dev when
// talking to a router that runs in ROUTER_STANDALONE mode (it skips SA
// token validation), so a developer laptop without GCP credentials can
// still exercise the /register + /heartbeat path.
func NoopTokenSource(_ context.Context, _ string) (string, error) {
	return "", nil
}

// MetadataServerTokenSource is the production TokenSource: it asks the GCP
// instance metadata server for an SA identity token scoped to the given
// audience. Works only on GCE VMs (incl. Confidential Space).
func MetadataServerTokenSource(ctx context.Context, audience string) (string, error) {
	const mdHost = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	u := mdHost + "?audience=" + url.QueryEscape(audience) + "&format=full"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d: %s", resp.StatusCode, string(body))
	}
	return string(bytes.TrimSpace(body)), nil
}
