//go:build !mobile

package shared

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// AWSSecretStore reads and writes OPRF shares in AWS Secrets Manager — the
// AWS-side counterpart to SecretStore (GCP). Encryption at rest is handled by
// Secrets Manager under the configured KMS CMK (empty = the account default
// aws/secretsmanager key); the stored value is the raw share as SecretBinary.
// Secret IDs match the GCP layout (oprfSecretID) so a share exported from GCP
// imports and resolves under the same name on both clouds.
type AWSSecretStore struct {
	sm       *secretsmanager.Client
	kmsKeyID string
}

// NewAWSSecretStore builds a store from the ambient AWS config (region +
// credentials from the instance role / env). kmsKeyID is the CMK used only
// when CREATING a secret; reads never need it (the role's kms:Decrypt does).
func NewAWSSecretStore(ctx context.Context, kmsKeyID string) (*AWSSecretStore, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}

	return &AWSSecretStore{sm: secretsmanager.NewFromConfig(cfg), kmsKeyID: kmsKeyID}, nil
}

// LoadOrCreateOPRFShare mirrors SecretStore.LoadOrCreateOPRFShare: returns the
// persistent share for (role, deploymentKey), generating + storing one on
// first boot. In normal operation the share is pre-seeded by the import tool,
// so this just reads.
func (s *AWSSecretStore) LoadOrCreateOPRFShare(ctx context.Context, role, deploymentKey string) ([]byte, error) {
	secretID := oprfSecretID(role, deploymentKey)

	share, err := s.load(ctx, secretID)
	if err == nil {
		if len(share) != oprfKeyShareSize {
			return nil, fmt.Errorf("oprf share %q has wrong length: got %d, want %d",
				secretID, len(share), oprfKeyShareSize)
		}

		return share, nil
	}

	if _, ok := errors.AsType[*smtypes.ResourceNotFoundException](err); !ok {
		return nil, fmt.Errorf("get secret %q: %w", secretID, err)
	}

	// Fail closed: the AWS share must be the GCP original, seeded out of band
	// (cmd/oprfshare import). Auto-minting a fresh random share here would
	// silently diverge the cross-cloud OPRF key -> wrong nullifiers, no alarm.
	return nil, fmt.Errorf("oprf share %q not found in AWS Secrets Manager; seed it from the GCP share via cmd/oprfshare before launching (refusing to auto-generate a divergent key)", secretID)
}

// StoreOPRFShare creates or overwrites the share for (role, deploymentKey).
// Used by the import tool to seed a GCP-exported share into AWS.
func (s *AWSSecretStore) StoreOPRFShare(ctx context.Context, role, deploymentKey string, share []byte) error {
	if len(share) != oprfKeyShareSize {
		return fmt.Errorf("oprf share has wrong length: got %d, want %d", len(share), oprfKeyShareSize)
	}

	secretID := oprfSecretID(role, deploymentKey)
	err := s.create(ctx, secretID, share)
	if _, ok := errors.AsType[*smtypes.ResourceExistsException](err); ok {
		_, perr := s.sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretID),
			SecretBinary: share,
		})

		return perr
	}

	return err
}

func (s *AWSSecretStore) load(ctx context.Context, secretID string) ([]byte, error) {
	out, err := s.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return nil, err
	}

	return out.SecretBinary, nil
}

func (s *AWSSecretStore) create(ctx context.Context, secretID string, share []byte) error {
	in := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretID),
		SecretBinary: share,
	}
	if s.kmsKeyID != "" {
		in.KmsKeyId = aws.String(s.kmsKeyID)
	}

	_, err := s.sm.CreateSecret(ctx, in)
	return err
}
