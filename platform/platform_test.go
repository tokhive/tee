package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
)

func TestSigningDigestSeparatesDomainsAndPayloadBoundaries(t *testing.T) {
	payload := []byte("same-payload")
	first, err := SigningDigest("tokenhive.receipt.v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SigningDigest("tokenhive.registration.v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different signing domains produced the same digest")
	}

	left, err := SigningDigest("ab", []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := SigningDigest("a", []byte("bc"))
	if err != nil {
		t.Fatal(err)
	}
	if left == right {
		t.Fatal("length framing did not separate domain and payload")
	}
}

func TestSigningDigestRejectsInvalidDomain(t *testing.T) {
	for _, domain := range []string{"", strings.Repeat("x", maxSigningDomainLength+1)} {
		if _, err := SigningDigest(domain, nil); err == nil {
			t.Fatalf("SigningDigest(%d-byte domain) succeeded", len(domain))
		}
	}
}

func TestVerifySignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(publicKeyDER)
	identity := Identity{PublicKeyDER: publicKeyDER, KeyID: keyID}

	digest, err := SigningDigest("tokenhive.test.v1", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := Signature{Algorithm: SignatureAlgorithmECDSAP256SHA256ASN1, KeyID: keyID, Value: value}

	if err := VerifySignature(identity, "tokenhive.test.v1", []byte("payload"), signature); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySignature(identity, "tokenhive.test.v1", []byte("modified"), signature); err == nil {
		t.Fatal("modified payload accepted")
	}
	signature.KeyID[0] ^= 0xff
	if err := VerifySignature(identity, "tokenhive.test.v1", []byte("payload"), signature); err == nil {
		t.Fatal("signature with a different key ID accepted")
	}
}

func TestVerifySignatureRejectsMislabeledCurve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha256.Sum256(publicKeyDER)
	identity := Identity{PublicKeyDER: publicKeyDER, KeyID: keyID}
	digest, err := SigningDigest("tokenhive.test.v1", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := Signature{Algorithm: SignatureAlgorithmECDSAP256SHA256ASN1, KeyID: keyID, Value: value}
	if err := VerifySignature(identity, "tokenhive.test.v1", []byte("payload"), signature); err == nil {
		t.Fatal("P-384 signature accepted as P-256")
	}
}
