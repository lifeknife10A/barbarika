package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519Signer_SignAndVerify(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	payload := []byte("Barbarika Evidence Provenance Test Data")

	// Sign payload
	signatureBase64 := signer.Sign(payload)
	if signatureBase64 == "" {
		t.Fatalf("Expected valid Base64 signature string")
	}

	// Verify valid signature
	isValid := signer.Verify(payload, signatureBase64)
	if !isValid {
		t.Fatalf("Signature verification failed for authentic payload")
	}

	// Verify invalid/tampered payload fails verification
	tamperedPayload := []byte("Barbarika TAMPERED Data")
	isTamperedValid := signer.Verify(tamperedPayload, signatureBase64)
	if isTamperedValid {
		t.Fatalf("Signature verification MUST fail for tampered payload")
	}
}

func TestLoadOrCreateSigner_PersistsStableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.key")

	// First call generates and persists the key.
	s1, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected key file to be written: %v", err)
	}

	// Second call must load the same key (stable identity across restarts).
	s2, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	if s1.PublicKeyBase64() != s2.PublicKeyBase64() {
		t.Fatalf("reloaded public key differs: %s vs %s", s1.PublicKeyBase64(), s2.PublicKeyBase64())
	}

	// A signature from the reloaded key verifies against the original.
	sig := s2.Sign([]byte("evidence"))
	if !s1.Verify([]byte("evidence"), sig) {
		t.Fatal("signature from persisted key failed to verify")
	}
}
