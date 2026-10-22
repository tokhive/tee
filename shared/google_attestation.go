package shared

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// GoogleAttestor verifies Google CVM attestation JWT against hardcoded Google roots.
// This implementation validates signature using Google's Attestation Verification root,
// verifies basic token structure, and is intentionally minimal per "surgical" scope.
type GoogleAttestor struct {
	rootCertPool *x509.CertPool
}

// A minimal set of root/intermediate certs used for verification.
const googleAttestationRootPEM = `-----BEGIN CERTIFICATE-----
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
uyT5CnJulxSC5CT1
-----END CERTIFICATE-----`

func NewGoogleAttestor() (*GoogleAttestor, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(googleAttestationRootPEM)) {
		return nil, fmt.Errorf("failed to load Google attestation root")
	}
	return &GoogleAttestor{rootCertPool: pool}, nil
}

// Validate verifies a compact JWS (JWT) from Google CVM attestation service.
// For simplicity, this validates the signature using embedded x5c certificate chain
// and checks certificate chain roots to our hardcoded pool.
func (g *GoogleAttestor) Validate(raw []byte, logger *Logger) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty GCP attestation report")
	}

	tokenStr := strings.TrimSpace(string(raw))
	parser := newGoogleJWTParser(0)

	// Custom keyfunc that extracts the leaf certificate from x5c header and verifies chain
	keyfunc := func(t *jwt.Token) (any, error) {
		hdr := t.Header
		x5c, ok := hdr["x5c"].([]any)
		if !ok || len(x5c) == 0 {
			return nil, fmt.Errorf("missing x5c header in GCP attestation JWT")
		}

		// Decode leaf cert (base64 DER)
		leafB64, _ := x5c[0].(string)
		der, err := decodeBase64URL(leafB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x5c leaf: %v", err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf certificate: %v", err)
		}

		// Build intermediates
		intermediates := x509.NewCertPool()
		for i := 1; i < len(x5c); i++ {
			seg, _ := x5c[i].(string)
			ider, err := decodeBase64URL(seg)
			if err != nil {
				continue
			}
			if cert, err := x509.ParseCertificate(ider); err == nil {
				intermediates.AddCert(cert)
			}
		}

		// Verify chain to our hardcoded Google root
		// Allow DigitalSignature key usage for JWT signing certificates
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         g.rootCertPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("x5c chain verification failed: %v", err)
		}
		return leaf.PublicKey, nil
	}

	// Parse and verify
	token, err := parser.Parse(tokenStr, keyfunc)
	if err != nil {
		// Extract timing information from JWT to diagnose clock skew
		parts := strings.Split(tokenStr, ".")
		if len(parts) >= 2 {
			if payload, decErr := base64.RawURLEncoding.DecodeString(parts[1]); decErr == nil {
				var claims map[string]any
				if jsonErr := json.Unmarshal(payload, &claims); jsonErr == nil {
					now := time.Now()
					timingInfo := fmt.Sprintf("JWT validation failed, diagnosing clock skew - Current time: %s", now.Format(time.RFC3339))

					if nbf, ok := claims["nbf"].(float64); ok {
						nbfTime := time.Unix(int64(nbf), 0)
						diff := now.Sub(nbfTime)
						timingInfo += fmt.Sprintf(" | nbf (not before): %s | Time until valid: %v",
							nbfTime.Format(time.RFC3339), -diff)
					}
					if iat, ok := claims["iat"].(float64); ok {
						iatTime := time.Unix(int64(iat), 0)
						diff := now.Sub(iatTime)
						timingInfo += fmt.Sprintf(" | iat (issued at): %s | Age: %v",
							iatTime.Format(time.RFC3339), diff)
					}
					if exp, ok := claims["exp"].(float64); ok {
						expTime := time.Unix(int64(exp), 0)
						diff := expTime.Sub(now)
						timingInfo += fmt.Sprintf(" | exp (expires): %s | Time until expiry: %v",
							expTime.Format(time.RFC3339), diff)
					}

					// Log the timing information using shared logger
					logger.Warn("JWT clock skew detected, retrying with leeway",
						zap.String("current_time", now.Format(time.RFC3339)),
						zap.String("timing_info", timingInfo))

					// Retry with 1-minute leeway to handle clock skew
					parserWithLeeway := newGoogleJWTParser(1 * time.Minute)
					token, retryErr := parserWithLeeway.Parse(tokenStr, keyfunc)
					if retryErr != nil {
						return fmt.Errorf("failed to parse/verify GCP attestation JWT even with 1-minute leeway: %v | %s", retryErr, timingInfo)
					}
					if !token.Valid {
						return fmt.Errorf("invalid GCP attestation JWT even with 1-minute leeway | %s", timingInfo)
					}
					// Success with leeway
					logger.Info("JWT validation succeeded with 1-minute leeway",
						zap.String("timing_info", timingInfo))
					return nil
				}
			}
		}
		return fmt.Errorf("failed to parse/verify GCP attestation JWT: %v", err)
	}
	if !token.Valid {
		return fmt.Errorf("invalid GCP attestation JWT")
	}

	// Basic claim presence checks could be added here based on your policy
	return nil
}

// newGoogleJWTParser keeps the attestation token policy identical for the
// initial parse and the clock-skew retry. Leeway relaxes only time checks; it
// must never relax the required expiration or accepted signature algorithm.
func newGoogleJWTParser(leeway time.Duration) *jwt.Parser {
	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256"}),
	}
	if leeway > 0 {
		options = append(options, jwt.WithLeeway(leeway))
	}
	return jwt.NewParser(options...)
}

// decodeBase64URL decodes a base64 or base64url-encoded string
func decodeBase64URL(s string) ([]byte, error) {
	// Try base64url without padding
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try base64url with padding
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try standard base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("failed to decode base64 segment")
}

// ValidateGCPAttestationAndExtractUserData validates GCP JWT signature and extracts userData from eat_nonce
func ValidateGCPAttestationAndExtractUserData(token []byte, logger *Logger) (string, error) {
	// Create attestor with Google root certs
	attestor, err := NewGoogleAttestor()
	if err != nil {
		return "", fmt.Errorf("failed to create Google attestor: %v", err)
	}

	// Validate JWT signature and certificate chain
	if err := attestor.Validate(token, logger); err != nil {
		return "", fmt.Errorf("JWT validation failed: %v", err)
	}

	// Parse JWT to extract claims (already validated above)
	tokenStr := strings.TrimSpace(string(token))
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	// Parse claims
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal claims: %v", err)
	}

	// Extract eat_nonce (can be string or string array)
	eatNonceRaw, ok := claims["eat_nonce"]
	if !ok {
		return "", fmt.Errorf("eat_nonce claim not found")
	}

	// Handle string (single nonce)
	if nonce, ok := eatNonceRaw.(string); ok {
		return nonce, nil
	}

	// Handle array (multiple nonces)
	if eatNonceArray, ok := eatNonceRaw.([]any); ok {
		if len(eatNonceArray) == 0 {
			return "", fmt.Errorf("eat_nonce array is empty")
		}
		nonce, ok := eatNonceArray[0].(string)
		if !ok {
			return "", fmt.Errorf("eat_nonce[0] is not a string")
		}
		return nonce, nil
	}

	return "", fmt.Errorf("eat_nonce is neither string nor array")
}

// ExtractImageDigestFromGCPAttestation extracts image_digest from GCP attestation token
func ExtractImageDigestFromGCPAttestation(token []byte, logger *Logger) (string, error) {
	// Create attestor with Google root certs
	attestor, err := NewGoogleAttestor()
	if err != nil {
		return "", fmt.Errorf("failed to create Google attestor: %v", err)
	}

	// Validate JWT signature and certificate chain
	if err := attestor.Validate(token, logger); err != nil {
		return "", fmt.Errorf("JWT validation failed: %v", err)
	}

	// Parse JWT to extract claims (already validated above)
	tokenStr := strings.TrimSpace(string(token))
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	// Parse claims
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal claims: %v", err)
	}

	// Extract submods.container.image_digest
	submods, ok := claims["submods"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("submods claim not found or not an object")
	}

	container, ok := submods["container"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("submods.container claim not found or not an object")
	}

	imageDigest, ok := container["image_digest"].(string)
	if !ok {
		return "", fmt.Errorf("submods.container.image_digest not found or not a string")
	}

	return imageDigest, nil
}
