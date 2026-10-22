package shared

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Address represents a 20-byte Ethereum address
type Address [20]byte

// Hex returns the hex string representation of the address with 0x prefix
func (a Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

// String returns the hex string representation (same as Hex)
func (a Address) String() string {
	return a.Hex()
}

// Bytes returns the address as a byte slice
func (a Address) Bytes() []byte {
	return a[:]
}

// HexToAddress parses a hex string (with or without 0x prefix) to an Address
func HexToAddress(s string) Address {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var a Address
	b, err := hex.DecodeString(s)
	if err != nil {
		return a
	}
	if len(b) > 20 {
		b = b[len(b)-20:]
	}
	copy(a[20-len(b):], b)
	return a
}

// BytesToAddress converts bytes to an Address, taking the last 20 bytes if longer
func BytesToAddress(b []byte) Address {
	var a Address
	if len(b) > 20 {
		b = b[len(b)-20:]
	}
	copy(a[20-len(b):], b)
	return a
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded Ethereum address
func IsHexAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Keccak256 calculates the Keccak-256 hash of the input data
func Keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// TextHash computes the Ethereum signed message hash
// This matches accounts.TextHash from go-ethereum
// Format: Keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
func TextHash(data []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(data))
	return Keccak256([]byte(prefix), data)
}

// GenerateKey generates a new secp256k1 private key
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return key.ToECDSA(), nil
}

// Sign creates a recoverable ECDSA signature
// The produced signature is in the [R || S || V] format where V is 0 or 1
// Returns a 65-byte signature
func Sign(hash []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("hash must be 32 bytes")
	}

	// Convert to secp256k1 private key
	privKey := secp256k1.PrivKeyFromBytes(priv.D.Bytes())

	// Sign with recovery - returns [V || R || S] format where V is recovery ID + 27
	sig := decredecdsa.SignCompact(privKey, hash, false)

	// Convert from [V || R || S] to [R || S || V] format
	// sig[0] contains the recovery ID + 27
	v := sig[0] - 27
	result := make([]byte, 65)
	copy(result[0:32], sig[1:33])   // R
	copy(result[32:64], sig[33:65]) // S
	result[64] = v                  // V (0 or 1)

	return result, nil
}

// SigToPub recovers the public key from a signature
// The signature should be in [R || S || V] format (65 bytes)
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	if len(sig) != 65 {
		return nil, errors.New("signature must be 65 bytes")
	}
	if len(hash) != 32 {
		return nil, errors.New("hash must be 32 bytes")
	}

	// Convert from [R || S || V] to [V || R || S] format for decred
	v := sig[64]
	if v >= 27 {
		v -= 27
	}

	compactSig := make([]byte, 65)
	compactSig[0] = v + 27              // Recovery ID + 27
	copy(compactSig[1:33], sig[0:32])   // R
	copy(compactSig[33:65], sig[32:64]) // S

	pubKey, _, err := decredecdsa.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil, err
	}

	return pubKey.ToECDSA(), nil
}

// PubkeyToAddress derives the Ethereum address from a public key
// Address = last 20 bytes of Keccak256(uncompressed public key without prefix)
func PubkeyToAddress(pub *ecdsa.PublicKey) Address {
	// Get uncompressed public key bytes (65 bytes with 0x04 prefix)
	// We need to remove the prefix for the hash
	pubBytes := make([]byte, 64)
	pub.X.FillBytes(pubBytes[0:32])
	pub.Y.FillBytes(pubBytes[32:64])

	hash := Keccak256(pubBytes)
	return BytesToAddress(hash[12:]) // Last 20 bytes
}

// FromECDSAPub exports a public key to uncompressed format (65 bytes with 04 prefix)
func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	result := make([]byte, 65)
	result[0] = 0x04
	pub.X.FillBytes(result[1:33])
	pub.Y.FillBytes(result[33:65])
	return result
}

// ToECDSAPub parses a public key from uncompressed format
func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	// Handle both compressed and uncompressed
	var x, y *big.Int
	if len(pub) == 65 && pub[0] == 0x04 {
		x = new(big.Int).SetBytes(pub[1:33])
		y = new(big.Int).SetBytes(pub[33:65])
	} else if len(pub) == 64 {
		x = new(big.Int).SetBytes(pub[0:32])
		y = new(big.Int).SetBytes(pub[32:64])
	} else {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}
}
