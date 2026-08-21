package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Signer wraps Ed25519 cryptographic signing capabilities.
type Signer struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewSigner creates a new Signer with a freshly generated Ed25519 keypair.
func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &Signer{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// NewSignerFromPrivateKey loads a Signer from existing Ed25519 private key bytes.
func NewSignerFromPrivateKey(privKeyBytes []byte) (*Signer, error) {
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)
	return &Signer{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

// PublicKey returns the raw Ed25519 public key bytes.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

// PublicKeyBase64 returns the Ed25519 public key encoded as a standard base64 string.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

// Sign signs the provided data using the Ed25519 private key.
func (s *Signer) Sign(data []byte) []byte {
	return ed25519.Sign(s.privateKey, data)
}

// SignBase64 signs data and returns the base64-encoded signature.
func (s *Signer) SignBase64(data []byte) string {
	sig := s.Sign(data)
	return base64.StdEncoding.EncodeToString(sig)
}

// Verify checks if an Ed25519 signature is valid for the given data and public key.
func Verify(pubKey ed25519.PublicKey, data, sig []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, data, sig)
}

// VerifyBase64 checks a base64-encoded signature against base64-encoded public key.
func VerifyBase64(pubKeyB64 string, data []byte, sigB64 string) (bool, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false, fmt.Errorf("invalid public key base64: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("invalid signature base64: %w", err)
	}
	return Verify(pubBytes, data, sigBytes), nil
}
