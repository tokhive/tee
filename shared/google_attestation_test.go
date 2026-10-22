package shared

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGoogleClockSkewParserRetainsAttestationPolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signRS256 := func(t *testing.T, claims jwt.MapClaims) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	parseRSA := func(parser *jwt.Parser, raw string) error {
		_, err := parser.Parse(raw, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
		return err
	}

	skewed := signRS256(t, jwt.MapClaims{"exp": time.Now().Add(-30 * time.Second).Unix()})
	if err := parseRSA(newGoogleJWTParser(0), skewed); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("zero-leeway skew result = %v, want expired", err)
	}
	if err := parseRSA(newGoogleJWTParser(time.Minute), skewed); err != nil {
		t.Fatalf("one-minute skew retry rejected valid RS256 token: %v", err)
	}

	missingExpiration := signRS256(t, jwt.MapClaims{"sub": "missing-exp"})
	if err := parseRSA(newGoogleJWTParser(time.Minute), missingExpiration); !errors.Is(err, jwt.ErrTokenRequiredClaimMissing) {
		t.Fatalf("skew retry missing-exp result = %v, want required-claim error", err)
	}

	hmacKey := []byte("not-an-rsa-key")
	wrongAlgorithm, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Minute).Unix()}).SignedString(hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newGoogleJWTParser(time.Minute).Parse(wrongAlgorithm, func(*jwt.Token) (any, error) { return hmacKey, nil })
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("skew retry wrong-alg result = %v, want signature-invalid", err)
	}
}
