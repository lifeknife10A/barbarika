package spool

import (
	"fmt"
	"os"
	"testing"

	"barbarika/agent/internal/normalizer"
)

func TestSpoolPushAndReplay(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := NewSpool(tmpDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}

	// Push 3 events
	for i := 1; i <= 3; i++ {
		evt := normalizer.Event{
			EventType:  "test_event",
			Source:     "test-host",
			Severity:   "info",
			OccurredAt: "2026-08-22T01:00:00Z",
			DetectedAt: "2026-08-22T01:00:00Z",
			Sequence:   uint64(i),
			Payload:    map[string]interface{}{"idx": i},
		}
		if err := sp.Push(evt); err != nil {
			t.Fatalf("failed to push event %d: %v", i, err)
		}
	}
	_ = sp.Close()

	// Re-open and verify replay
	sp2, err := NewSpool(tmpDir, 1024*1024)
	if err != nil {
		t.Fatalf("failed to reopen spool: %v", err)
	}
	defer sp2.Close()

	replayed, err := sp2.ReplayUnacknowledged()
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if len(replayed) != 3 {
		t.Fatalf("expected 3 replayed events, got %d", len(replayed))
	}
	if replayed[0].Sequence != 1 || replayed[1].Sequence != 2 || replayed[2].Sequence != 3 {
		t.Fatalf("sequence order mismatch: %v", replayed)
	}
}

func TestSpoolBoundedSizeEviction(t *testing.T) {
	tmpDir := t.TempDir()

	// Tiny bounded spool: 500 bytes max, 100 bytes per segment
	sp, err := NewSpool(tmpDir, 500)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	sp.segmentMax = 100 // force rotation every 100 bytes

	for i := 1; i <= 20; i++ {
		evt := normalizer.Event{
			EventType: "overflow_test",
			Source:    "host",
			Sequence:  uint64(i),
			Payload:   map[string]interface{}{"padding": fmt.Sprintf("long_padding_data_%d", i)},
		}
		_ = sp.Push(evt)
	}
	_ = sp.Close()

	// Verify total size on disk is bounded
	segments, err := sp.listSegments()
	if err != nil {
		t.Fatalf("failed to list segments: %v", err)
	}

	var totalSize int64
	for _, s := range segments {
		fi, _ := osStat(s)
		totalSize += fi
	}

	// Should not exceed max bounds significantly
	if totalSize > 1500 {
		t.Fatalf("spool size %d exceeded expected bound", totalSize)
	}
}

func osStat(p string) (int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
