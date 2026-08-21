package batcher

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"barbarika/agent/internal/normalizer"
	"barbarika/agent/internal/signer"
)

func TestBatcherSizeFlushAndSignature(t *testing.T) {
	sig, err := signer.NewSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	b := NewBatcher(Config{
		AgentID:       "primary-srv-01",
		MaxBatchSize:  3,
		FlushInterval: 10 * time.Second, // high interval so size triggers flush
	}, sig)

	// Add 3 events
	for i := 1; i <= 3; i++ {
		b.Add(normalizer.Event{
			EventType:  "ssh_auth_failure",
			Source:     "primary-srv-01",
			Sequence:   uint64(i),
			RawHash:    "dummy-hash",
			DetectedAt: "2026-08-22T01:00:00Z",
		})
	}

	select {
	case batch := <-b.OutChannel():
		if batch.EventCount != 3 {
			t.Fatalf("expected 3 events in batch, got %d", batch.EventCount)
		}
		if batch.SequenceStart != 1 || batch.SequenceEnd != 3 {
			t.Fatalf("sequence start/end mismatch: %d -> %d", batch.SequenceStart, batch.SequenceEnd)
		}

		// Verify signature
		sigSummary := struct {
			BatchID    string `json:"batch_id"`
			AgentID    string `json:"agent_id"`
			BatchHash  string `json:"batch_hash"`
			EventCount int    `json:"event_count"`
			CreatedAt  string `json:"created_at"`
		}{
			BatchID:    batch.BatchID,
			AgentID:    batch.AgentID,
			BatchHash:  batch.BatchHash,
			EventCount: batch.EventCount,
			CreatedAt:  batch.CreatedAt,
		}
		sigBytes, _ := json.Marshal(sigSummary)

		valid, err := signer.VerifyBase64(batch.PublicKey, sigBytes, batch.Signature)
		if err != nil || !valid {
			t.Fatalf("batch signature verification failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for size-triggered batch flush")
	}
}

func TestBatcherTimerFlush(t *testing.T) {
	sig, _ := signer.NewSigner()
	b := NewBatcher(Config{
		AgentID:       "primary-srv-01",
		MaxBatchSize:  50,
		FlushInterval: 50 * time.Millisecond,
	}, sig)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go b.Start(ctx)

	b.Add(normalizer.Event{
		EventType: "http_exploit_pattern",
		Source:    "primary-srv-01",
		Sequence:  10,
	})

	select {
	case batch := <-b.OutChannel():
		if batch.EventCount != 1 {
			t.Fatalf("expected 1 event, got %d", batch.EventCount)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for timer-triggered batch flush")
	}
}
