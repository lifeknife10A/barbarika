package signer

import (
	"testing"
)

func TestSignerLifecycle(t *testing.T) {
	s, err := NewSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	data := []byte("Barbarika: Evidence-Preserving Incident Readiness")
	sig := s.Sign(data)
	if len(sig) != 64 {
		t.Fatalf("expected 64 byte signature, got %d", len(sig))
	}

	if !Verify(s.PublicKey(), data, sig) {
		t.Fatal("signature verification failed")
	}

	// Corrupt data
	corruptData := []byte("Corrupted: Evidence-Preserving Incident Readiness")
	if Verify(s.PublicKey(), corruptData, sig) {
		t.Fatal("signature verified corrupted data, expected failure")
	}

	// Base64 roundtrip
	pubB64 := s.PublicKeyBase64()
	sigB64 := s.SignBase64(data)

	valid, err := VerifyBase64(pubB64, data, sigB64)
	if err != nil {
		t.Fatalf("VerifyBase64 errored: %v", err)
	}
	if !valid {
		t.Fatal("VerifyBase64 returned false for valid signature")
	}
}
