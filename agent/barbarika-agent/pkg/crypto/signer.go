package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// Signer handles Ed25519 keypair loading, signing, and signature verification.
type Signer struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// NewSigner initializes or loads an Ed25519 keypair.
func NewSigner() (*Signer, error) {
	// Generate a new ephemeral keypair in memory (or load from disk if present)
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	return &Signer{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

// Sign signs raw data using the private key and returns a Base64-encoded signature string.
func (s *Signer) Sign(data []byte) string {
	signature := ed25519.Sign(s.PrivateKey, data)
	return base64.StdEncoding.EncodeToString(signature)
}

// Verify verifies a Base64 signature against raw data using the public key.
func (s *Signer) Verify(data []byte, signatureBase64 string) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.PublicKey, data, sigBytes)
}

// PublicKeyBase64 returns the Base64 representation of the agent's Public Key.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.PublicKey)
}

// SavePrivateKey exports the private key to a restricted file for persistence if needed.
func (s *Signer) SavePrivateKey(filepath string) error {
	return os.WriteFile(filepath, s.PrivateKey, 0600)
}
