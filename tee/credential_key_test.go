package tee

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tokhive/tee/platform/simulated"
	"github.com/tokhive/tee/proof"
)

func TestServeAttestedCredentialKey(t *testing.T) {
	inbox, err := GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	epoch, err := simulated.NewEpoch()
	if err != nil {
		t.Fatalf("simulated epoch: %v", err)
	}
	policyHash := sha256.Sum256([]byte("deployment policy"))
	nonce := bytes.Repeat([]byte{0x5a}, proof.CredentialKeyNonceLength)

	request := httptest.NewRequest(http.MethodGet, "/v1/credential-key?nonce="+hex.EncodeToString(nonce), nil)
	response := httptest.NewRecorder()
	ServeAttestedCredentialKey(inbox, proof.NewSigner(epoch), policyHash, response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	var payload struct {
		KeyID       string `json:"key_id"`
		PublicKey   string `json:"public_key"`
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	public := inbox.Public()
	if payload.KeyID != base64.StdEncoding.EncodeToString(public.KeyID[:]) {
		t.Fatal("response key ID does not match the inbox key")
	}
	if payload.PublicKey != base64.StdEncoding.EncodeToString(public.PublicKey) {
		t.Fatal("response public key does not match the inbox key")
	}

	statement, err := base64.StdEncoding.DecodeString(payload.Attestation)
	if err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	signed, err := proof.DecodeAndVerifyCredentialKey(statement, proof.CredentialKeyVerifyOptions{
		Nonce:            nonce,
		PolicyHash:       policyHash[:],
		AllowedPlatforms: []string{simulated.Platform},
		RequireEvidence:  true,
	})
	if err != nil {
		t.Fatalf("verify attestation: %v", err)
	}
	if !bytes.Equal(signed.Statement.InboxPublic, public.PublicKey) {
		t.Fatal("statement does not bind the served inbox key")
	}
}

func TestServeAttestedCredentialKeyRejectsBadNonce(t *testing.T) {
	inbox, err := GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	epoch, err := simulated.NewEpoch()
	if err != nil {
		t.Fatalf("simulated epoch: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/credential-key?nonce=00", nil)
	response := httptest.NewRecorder()
	ServeAttestedCredentialKey(inbox, proof.NewSigner(epoch), [32]byte{}, response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestServeAttestedCredentialKeyRequiresSigner(t *testing.T) {
	inbox, err := GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	nonce := hex.EncodeToString(bytes.Repeat([]byte{1}, proof.CredentialKeyNonceLength))

	request := httptest.NewRequest(http.MethodGet, "/v1/credential-key?nonce="+nonce, nil)
	response := httptest.NewRecorder()
	ServeAttestedCredentialKey(inbox, nil, [32]byte{}, response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}
