package proof

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/tokhive/tee/platform"
)

func testInboxKey(t *testing.T) (keyID [32]byte, publicDER []byte) {
	t.Helper()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	publicDER, err = x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("marshal inbox key: %v", err)
	}
	return sha256.Sum256(publicDER), publicDER
}

func testCredentialKeyStatement(t *testing.T, nonce []byte) CredentialKeyStatement {
	t.Helper()

	keyID, publicDER := testInboxKey(t)
	return CredentialKeyStatement{
		Version:     VersionV1,
		Nonce:       nonce,
		InboxKeyID:  keyID[:],
		InboxPublic: publicDER,
		PolicyHash:  digestOf([]byte("deployment policy")),
		IssuedAt:    time.Now().Unix(),
	}
}

func signTestCredentialKey(t *testing.T, statement CredentialKeyStatement) (SignedCredentialKey, *testEpoch) {
	t.Helper()

	signer := NewSigner(newTestEpoch(t))
	signed, err := signer.SignCredentialKey(statement)
	if err != nil {
		t.Fatalf("sign credential key: %v", err)
	}
	return signed, signer.epoch.(*testEpoch)
}

func TestCredentialKeySignAndVerify(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	statement := testCredentialKeyStatement(t, nonce)
	signed, epoch := signTestCredentialKey(t, statement)

	if len(signed.Statement.Attestation.Evidence) == 0 {
		t.Fatal("signed statement omitted the evidence")
	}
	if got := signed.Signature.KeyID; got != epoch.identity.KeyID {
		t.Fatalf("signature key ID %x, want %x", got, epoch.identity.KeyID)
	}

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce:            nonce,
		PolicyHash:       statement.PolicyHash,
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		RequireEvidence:  true,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCredentialKeyRejectsNonceMismatch(t *testing.T) {
	statement := testCredentialKeyStatement(t, digestOf([]byte("nonce")))
	signed, _ := signTestCredentialKey(t, statement)

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce: digestOf([]byte("another nonce")),
	})
	if !errors.Is(err, ErrCredentialKeyNonceMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrCredentialKeyNonceMismatch)
	}
}

func TestCredentialKeyRejectsPolicyMismatch(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	signed, _ := signTestCredentialKey(t, testCredentialKeyStatement(t, nonce))

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce:      nonce,
		PolicyHash: digestOf([]byte("another policy")),
	})
	if !errors.Is(err, ErrCredentialKeyPolicyMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrCredentialKeyPolicyMismatch)
	}
}

func TestCredentialKeyRejectsSwappedInboxKey(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	signed, _ := signTestCredentialKey(t, testCredentialKeyStatement(t, nonce))

	// A relay cannot swap the key: either the statement is edited (the
	// signature no longer verifies) or only the transport fields are edited
	// (the provider compares them with the statement).
	keyID, publicDER := testInboxKey(t)
	signed.Statement.InboxKeyID = keyID[:]
	signed.Statement.InboxPublic = publicDER

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce:            nonce,
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		RequireEvidence:  true,
	})
	if err == nil {
		t.Fatal("verification accepted a statement with a swapped inbox key")
	}
}

func TestCredentialKeyRejectsWrongPlatform(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	signed, _ := signTestCredentialKey(t, testCredentialKeyStatement(t, nonce))

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce:            nonce,
		AllowedPlatforms: []string{"simulated"},
	})
	if !errors.Is(err, ErrPlatformNotAllowed) {
		t.Fatalf("error = %v, want %v", err, ErrPlatformNotAllowed)
	}
}

func TestCredentialKeyRejectsDifferentDomain(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	signed, _ := signTestCredentialKey(t, testCredentialKeyStatement(t, nonce))

	identity, err := signed.Statement.Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	encoded, err := signed.Statement.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := platform.VerifySignature(identity, ReceiptSigningDomain, encoded, signed.Signature); err == nil {
		t.Fatal("credential-key signature verified under the receipt domain")
	}
}

func TestCredentialKeyRejectsBadInboxKey(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	statement := testCredentialKeyStatement(t, nonce)
	statement.InboxKeyID[0] ^= 0xff

	signer := NewSigner(newTestEpoch(t))
	if _, err := signer.SignCredentialKey(statement); !errors.Is(err, ErrInvalidInboxKey) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidInboxKey)
	}
}

func TestCredentialKeyRequiresEvidence(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	statement := testCredentialKeyStatement(t, nonce)
	base := newTestEpoch(t)
	identity := base.identity
	identity.Evidence = nil
	epoch := &testEpoch{key: base.key, identity: identity}

	if _, err := NewSigner(epoch).SignCredentialKey(statement); !errors.Is(err, ErrEvidenceRequired) {
		t.Fatalf("error = %v, want %v", err, ErrEvidenceRequired)
	}
}

func TestCredentialKeyRejectsOldStatement(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	statement := testCredentialKeyStatement(t, nonce)
	statement.IssuedAt = time.Now().Add(-time.Hour).Unix()
	signed, _ := signTestCredentialKey(t, statement)

	err := VerifyCredentialKey(signed, CredentialKeyVerifyOptions{
		Nonce:  nonce,
		MaxAge: time.Minute,
	})
	if !errors.Is(err, ErrCredentialKeyTooOld) {
		t.Fatalf("error = %v, want %v", err, ErrCredentialKeyTooOld)
	}
}

func TestCredentialKeyCanonicalRoundTrip(t *testing.T) {
	nonce := digestOf([]byte("nonce"))
	signed, _ := signTestCredentialKey(t, testCredentialKeyStatement(t, nonce))

	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeCredentialKey(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := VerifyCredentialKey(decoded, CredentialKeyVerifyOptions{Nonce: nonce}); err != nil {
		t.Fatalf("verify decoded: %v", err)
	}
}
