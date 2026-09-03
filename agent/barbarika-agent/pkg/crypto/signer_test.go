package crypto

import (
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
