//go:build !mobile

package shared

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// GoogleKMSProvider wraps a Google Cloud KMS key for envelope encryption.
// Used to wrap the data encryption key under which the OPRF share is
// stored in Secret Manager — same envelope format used by the legacy
// EnclaveCache, so existing stored shares decrypt unchanged.
type GoogleKMSProvider struct {
	kmsClient   *kms.KeyManagementClient
	keyResource string
}

// DataKey is a freshly-generated 32-byte AES key plus its KMS-wrapped form.
// The plaintext is for in-memory use only and must never be persisted.
type DataKey struct {
	Plaintext      []byte
	CiphertextBlob []byte
}

// NewGoogleKMSProvider builds a KMS client bound to a specific crypto key.
func NewGoogleKMSProvider(ctx context.Context, projectID, location, keyRing, keyName string) (*GoogleKMSProvider, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create GCP KMS client: %w", err)
	}
	keyResource := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID, location, keyRing, keyName)
	return &GoogleKMSProvider{kmsClient: client, keyResource: keyResource}, nil
}

// GenerateDataKey returns a new 32-byte random key plus its KMS-wrapped form.
// The plaintext is for in-memory AES-GCM use; the ciphertext blob is what
// gets persisted alongside the encrypted payload.
func (p *GoogleKMSProvider) GenerateDataKey(ctx context.Context) (*DataKey, error) {
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("generate random data key: %w", err)
	}
	resp, err := p.kmsClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      p.keyResource,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms Encrypt: %w", err)
	}
	return &DataKey{Plaintext: plaintext, CiphertextBlob: resp.Ciphertext}, nil
}

// DecryptDataKey unwraps a previously-generated data key. The returned
// plaintext is for in-memory use only.
func (p *GoogleKMSProvider) DecryptDataKey(ctx context.Context, ciphertextBlob []byte) ([]byte, error) {
	if len(ciphertextBlob) == 0 {
		return nil, errors.New("kms: missing wrapped data key")
	}
	resp, err := p.kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       p.keyResource,
		Ciphertext: ciphertextBlob,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms Decrypt: %w", err)
	}
	return resp.Plaintext, nil
}

// aesGCMEncrypt encrypts data with the supplied 32-byte key and prepends
// the nonce. Layout: nonce(12) || ciphertext+tag.
func aesGCMEncrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("aes-gcm: generate nonce: %w", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, data, nil)...), nil
}

// aesGCMDecrypt reverses aesGCMEncrypt.
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("aes-gcm: ciphertext too short")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes new gcm: %w", err)
	}
	return gcm, nil
}
