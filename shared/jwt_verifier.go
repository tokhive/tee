package shared

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

// ClientAuthReadTimeout bounds how long a TEE waits for the client's
// first envelope (ClientAuth). A misbehaving or slow client must not
// hold open a connection indefinitely before authenticating.
const ClientAuthReadTimeout = 5 * time.Second

// AllocationJWTClaims mirrors router/signer.AllocClaims — the shape of
// the JWT minted at /allocate. Kept in shared (not router/signer) so
// both TEEs can decode it without depending on the router module.
type AllocationJWTClaims struct {
	TEEKAddr    string `json:"teek_addr"`
	TEETAddr    string `json:"teet_addr"`
	ClientNonce string `json:"client_nonce"`
	jwt.RegisteredClaims
}

// ParseECDSAPublicKeyPEM decodes a PEM-encoded SPKI public key and
// returns it as *ecdsa.PublicKey. Rejects non-EC keys.
func ParseECDSAPublicKeyPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("jwt: PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt: parse PKIX public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwt: expected ECDSA public key, got %T", pub)
	}
	return ec, nil
}

// VerifyAllocationJWT validates an allocation JWT minted by the router:
//   - ES256 signature against pubKey
//   - `exp` not passed (jwt library enforces by default)
//   - `iss` equals expectedIssuer (defense in depth: lets ops scope a key
//     rotation by changing the issuer string)
//   - `aud` claim contains expectedPairID
func VerifyAllocationJWT(token string, pubKey *ecdsa.PublicKey, expectedIssuer, expectedPairID string) (*AllocationJWTClaims, error) {
	if pubKey == nil {
		return nil, errors.New("jwt: no public key configured")
	}
	if expectedIssuer == "" {
		return nil, errors.New("jwt: empty expected issuer")
	}
	if expectedPairID == "" {
		return nil, errors.New("jwt: empty expected pair_id")
	}

	claims := &AllocationJWTClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuer(expectedIssuer), jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, fmt.Errorf("jwt: parse/verify: %w", err)
	}

	if !slices.Contains(claims.Audience, expectedPairID) {
		return nil, fmt.Errorf("jwt: aud %v does not contain pair_id %q",
			claims.Audience, expectedPairID)
	}

	return claims, nil
}

// ReadAndVerifyClientAuth consumes the first envelope on a client WS
// connection, expects it to be ClientAuth, and validates the embedded
// allocation JWT. Returns the validated claims on success; on any
// failure the caller should close the connection.
//
// jtiTracker (optional, may be nil) provides replay protection: when
// non-nil, the JWT's jti is rejected if it was already consumed.
//
// The connection's read deadline is set and cleared by this function
// (5s, controlled by ClientAuthReadTimeout). Subsequent reads have no
// deadline unless the caller reinstates one.
// Returns the verified claims and the client-reported build version (empty for
// pre-versioning clients), so callers can log which build a session came from.
func ReadAndVerifyClientAuth(conn *websocket.Conn, pubKey *ecdsa.PublicKey, expectedIssuer, expectedPairID string, jtiTracker *JTITracker) (*AllocationJWTClaims, string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(ClientAuthReadTimeout)); err != nil {
		return nil, "", fmt.Errorf("set read deadline: %w", err)
	}
	_, msgBytes, err := conn.ReadMessage()
	if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
		return nil, "", fmt.Errorf("clear read deadline: %w", clearErr)
	}
	if err != nil {
		return nil, "", fmt.Errorf("read ClientAuth envelope: %w", err)
	}

	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return nil, "", fmt.Errorf("parse first envelope: %w", err)
	}
	auth, ok := env.Payload.(*teeproto.Envelope_ClientAuth)
	if !ok {
		return nil, "", fmt.Errorf("expected ClientAuth as first envelope, got %T", env.Payload)
	}
	clientVersion := auth.ClientAuth.GetClientVersion()
	claims, err := VerifyAllocationJWT(auth.ClientAuth.GetJwt(), pubKey, expectedIssuer, expectedPairID)
	if err != nil {
		return nil, clientVersion, err
	}
	if jtiTracker != nil {
		if claims.ExpiresAt == nil {
			return nil, clientVersion, errors.New("jwt: missing exp claim (cannot bound jti tracking)")
		}
		if err := jtiTracker.Use(claims.ID, claims.ExpiresAt.Time, time.Now()); err != nil {
			return nil, clientVersion, fmt.Errorf("jwt replay check: %w", err)
		}
	}
	return claims, clientVersion, nil
}
