//go:build !mobile

package shared

import (
	"context"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretspb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// oprfKeyShareSize is the byte length of each side's MPC OPRF share.
// Must match across TEE_K and TEE_T; do not change without a coordinated
// re-init of all stored shares.
const oprfKeyShareSize = 16

// SecretStore reads and writes envelope-encrypted OPRF shares in GCP
// Secret Manager. The on-disk payload format is JSON
// `{"data": <aes-gcm(plain, dek)>, "key": <kms_encrypt(dek)>}` — identical
// to what the deleted EnclaveCache wrote, so existing stored shares are
// loaded unchanged.
type SecretStore struct {
	sm        *secretmanager.Client
	kms       *GoogleKMSProvider
	projectID string
}

// NewSecretStore constructs a store ready to load or create OPRF shares.
// projectID is the GCP project hosting the Secret Manager secrets; the
// kms* arguments identify the KMS key used to wrap each share's DEK.
func NewSecretStore(ctx context.Context, projectID, kmsLocation, kmsKeyRing, kmsKey string) (*SecretStore, error) {
	kms, err := NewGoogleKMSProvider(ctx, projectID, kmsLocation, kmsKeyRing, kmsKey)
	if err != nil {
		return nil, fmt.Errorf("kms provider: %w", err)
	}
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("secret manager client: %w", err)
	}
	return &SecretStore{sm: sm, kms: kms, projectID: projectID}, nil
}

// LoadOrCreateOPRFShare returns this TEE's persistent OPRF key share for
// the named deployment. role is "tee_k" or "tee_t"; deploymentKey is the
// per-deployment discriminator (e.g. "eu.tk.reclaimprotocol.org"). On
// first boot the share is generated, encrypted, and stored; subsequent
// boots return the same bytes.
//
// Returns the static OPRF share name format used by the legacy EnclaveCache
// so a fresh V2 build picks up shares written by V1 without re-keying.
func (s *SecretStore) LoadOrCreateOPRFShare(ctx context.Context, role, deploymentKey string) ([]byte, error) {
	secretID := oprfSecretID(role, deploymentKey)

	share, err := s.load(ctx, secretID)
	if err == nil {
		if len(share) != oprfKeyShareSize {
			return nil, fmt.Errorf("oprf share %q has wrong length: got %d, want %d",
				secretID, len(share), oprfKeyShareSize)
		}
		return share, nil
	}
	if !isNotFound(err) {
		return nil, fmt.Errorf("load existing oprf share: %w", err)
	}

	// First boot: generate, store, return.
	share = make([]byte, oprfKeyShareSize)
	if _, err := rand.Read(share); err != nil {
		return nil, fmt.Errorf("generate oprf share: %w", err)
	}
	if err := s.store(ctx, secretID, share); err != nil {
		return nil, fmt.Errorf("persist new oprf share: %w", err)
	}
	return share, nil
}

// LoadExistingOPRFShare loads an existing share and never creates one — used
// by the export tool so a wrong (role, deploymentKey) errors out instead of
// silently minting a new prod-named secret.
func (s *SecretStore) LoadExistingOPRFShare(ctx context.Context, role, deploymentKey string) ([]byte, error) {
	secretID := oprfSecretID(role, deploymentKey)
	share, err := s.load(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if len(share) != oprfKeyShareSize {
		return nil, fmt.Errorf("oprf share %q has wrong length: got %d, want %d",
			secretID, len(share), oprfKeyShareSize)
	}
	return share, nil
}

func (s *SecretStore) load(ctx context.Context, secretID string) ([]byte, error) {
	resp, err := s.sm.AccessSecretVersion(ctx, &secretspb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", s.projectID, secretID),
	})
	if err != nil {
		return nil, err
	}
	return s.unwrap(ctx, resp.Payload.GetData())
}

func (s *SecretStore) store(ctx context.Context, secretID string, plain []byte) error {
	payload, err := s.wrap(ctx, plain)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}
	// CreateSecret may return AlreadyExists when an older deployment created
	// the container but no version exists yet — treat that as success and
	// proceed to AddSecretVersion.
	_, err = s.sm.CreateSecret(ctx, &secretspb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", s.projectID),
		SecretId: secretID,
		Secret: &secretspb.Secret{
			Replication: &secretspb.Replication{
				Replication: &secretspb.Replication_Automatic_{},
			},
		},
	})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("create secret %q: %w", secretID, err)
	}
	_, err = s.sm.AddSecretVersion(ctx, &secretspb.AddSecretVersionRequest{
		Parent:  fmt.Sprintf("projects/%s/secrets/%s", s.projectID, secretID),
		Payload: &secretspb.SecretPayload{Data: payload},
	})
	if err != nil {
		return fmt.Errorf("add version: %w", err)
	}
	return nil
}

// envelope is the on-disk JSON shape. Stable across V1 and V2.
type envelope struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

func (s *SecretStore) wrap(ctx context.Context, plain []byte) ([]byte, error) {
	dk, err := s.kms.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("generate dek: %w", err)
	}
	ciphertext, err := aesGCMEncrypt(dk.Plaintext, plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Data: ciphertext, Key: dk.CiphertextBlob})
}

func (s *SecretStore) unwrap(ctx context.Context, payload []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	if len(env.Key) == 0 {
		return nil, errors.New("envelope missing wrapped dek")
	}
	dek, err := s.kms.DecryptDataKey(ctx, env.Key)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	return aesGCMDecrypt(dek, env.Data)
}

// oprfSecretID returns the Secret Manager resource ID for a given
// (role, deploymentKey) pair. Format matches the legacy EnclaveCache:
//
//	sanitize("cache-<role>-<deploymentKey>-oprf-key-share")
//
// where sanitize replaces '.' and '_' with '-'. Existing secrets written
// under the V1 layout are resolved here unchanged.
func oprfSecretID(role, deploymentKey string) string {
	return sanitizeSecretID(fmt.Sprintf("cache-%s-%s-oprf-key-share", role, deploymentKey))
}

func sanitizeSecretID(id string) string {
	id = strings.ReplaceAll(id, ".", "-")
	id = strings.ReplaceAll(id, "_", "-")
	return id
}

func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}
