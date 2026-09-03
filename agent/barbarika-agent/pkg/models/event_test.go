package models

import (
	"testing"
	"time"
)

func TestLogEvent_ComputeHash(t *testing.T) {
	event := LogEvent{
		Sequence:   101,
		Source:     "auth",
		Timestamp:  time.Date(2026, 8, 19, 10, 12, 0, 0, time.UTC),
		RawContent: "Failed password for root from 192.168.1.105",
	}

	hash1 := event.ComputeHash()
	if hash1 == "" {
		t.Fatalf("Expected non-empty SHA-256 hash")
	}

	hash2 := event.ComputeHash()
	if hash1 != hash2 {
		t.Fatalf("SHA-256 hash must be deterministic. Got %s and %s", hash1, hash2)
	}

	if len(hash1) != 64 {
		t.Fatalf("Expected 64-char hex SHA-256 hash, got length %d", len(hash1))
	}
}
