package shared

import (
	"crypto/ecdsa"
	"fmt"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"google.golang.org/protobuf/proto"
)

// Single Session Mode: Cryptographic signing infrastructure

// Simple protobuf marshaling functions for internal transcript storage
// (These are NOT used for signing - only for storing/loading transcript data)

// MarshalRequestRedactionRangesProtobuf marshals request redaction ranges for transcript storage
func MarshalRequestRedactionRangesProtobuf(ranges []RequestRedactionRange) ([]byte, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range ranges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:  int32(r.Start),
			Length: int32(r.Length),
			Type:   r.Type,
		})
	}

	wrapper := &teeproto.RedactedRequest{RedactionRanges: pbRanges}
	return proto.Marshal(wrapper)
}

// UnmarshalRequestRedactionRangesProtobuf unmarshals request redaction ranges from transcript storage
func UnmarshalRequestRedactionRangesProtobuf(data []byte) ([]RequestRedactionRange, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var wrapper teeproto.RedactedRequest
	if err := proto.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf wrapper: %v", err)
	}

	if len(wrapper.RedactionRanges) == 0 {
		return nil, nil
	}

	ranges := make([]RequestRedactionRange, len(wrapper.RedactionRanges))
	for i, pbRange := range wrapper.RedactionRanges {
		ranges[i] = RequestRedactionRange{
			Start:  int(pbRange.Start),
			Length: int(pbRange.Length),
			Type:   pbRange.Type,
		}
	}

	return ranges, nil
}

// SigningKeyPair represents a cryptographic ECDSA signing key pair for Ethereum-style signatures
type SigningKeyPair struct {
	PrivateKey *ecdsa.PrivateKey `json:"private_key"`
	PublicKey  *ecdsa.PublicKey  `json:"public_key"`
}

// GenerateSigningKeyPair generates a new ECDSA signing key pair using secp256k1 curve (ETH compatible)
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	// Use secp256k1 key generation (ETH compatible)
	privateKey, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %v", err)
	}

	return &SigningKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// SignData signs the given data using Ethereum-style signatures
func (kp *SigningKeyPair) SignData(data []byte) ([]byte, error) {
	// Use standard Ethereum message signing (includes prefix)
	hash := TextHash(data)

	// Sign the hash - this returns a 65-byte signature with recovery ID
	signature, err := Sign(hash, kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data with ETH style: %v", err)
	}

	return signature, nil
}

// VerifySignature verifies an Ethereum-style signature against the given data using a public key
func VerifySignature(data []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	if len(signature) != 65 {
		return fmt.Errorf("invalid ETH signature length: expected 65 bytes, got %d", len(signature))
	}

	// Use standard Ethereum message signing (includes prefix)
	hash := TextHash(data)

	// Recover public key from signature
	recoveredPubKey, err := SigToPub(hash, signature)
	if err != nil {
		return fmt.Errorf("failed to recover public key from signature: %v", err)
	}

	// Compare recovered public key with expected public key
	expectedAddress := PubkeyToAddress(publicKey)
	recoveredAddress := PubkeyToAddress(recoveredPubKey)

	if expectedAddress != recoveredAddress {
		return fmt.Errorf("signature verification failed: expected address %s, got %s",
			expectedAddress.Hex(), recoveredAddress.Hex())
	}

	return nil
}

// VerifySignature method on SigningKeyPair
func (kp *SigningKeyPair) VerifySignature(data []byte, signature []byte) bool {
	err := VerifySignature(data, signature, kp.PublicKey)
	return err == nil
}

// GetEthAddress returns the Ethereum address for this key pair
func (kp *SigningKeyPair) GetEthAddress() Address {
	return PubkeyToAddress(kp.PublicKey)
}

// VerifySignatureWithETH verifies a signature using Ethereum-style verification with an address
func VerifySignatureWithETH(data []byte, signature []byte, expectedAddress Address) error {
	return VerifyEthSignature(data, signature, expectedAddress)
}

// VerifyEthSignature verifies an Ethereum-style signature against the given data and address
func VerifyEthSignature(data []byte, signature []byte, expectedAddress Address) error {
	if len(signature) != 65 {
		return fmt.Errorf("invalid ETH signature length: expected 65 bytes, got %d", len(signature))
	}

	// Use standard Ethereum message signing (includes prefix)
	hash := TextHash(data)

	// Recover public key from signature
	recoveredPubKey, err := SigToPub(hash, signature)
	if err != nil {
		return fmt.Errorf("failed to recover public key from signature: %v", err)
	}

	// Derive address from recovered public key
	recoveredAddress := PubkeyToAddress(recoveredPubKey)

	// Verify address matches
	if recoveredAddress != expectedAddress {
		return fmt.Errorf("signature verification failed: expected address %s, got %s",
			expectedAddress.Hex(), recoveredAddress.Hex())
	}

	return nil
}

// GetEthAddress returns the Ethereum address for a given public key
func GetEthAddress(publicKey *ecdsa.PublicKey) Address {
	return PubkeyToAddress(publicKey)
}
