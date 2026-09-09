package collector

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"barbarika-agent/pkg/models"
)

// stream() should turn each non-empty journal line into one hashed LogEvent,
// tagged source="journald", using the shared restart-durable sequence.
func TestJournaldStreamEmitsEvents(t *testing.T) {
	seq, err := OpenSeqStore(filepath.Join(t.TempDir(), "seq.state"), 100)
	if err != nil {
		t.Fatalf("OpenSeqStore: %v", err)
	}
	out := make(chan models.LogEvent, 8)
	// Note the blank line in the middle — it must be skipped.
	input := strings.NewReader(
		"2026-09-08T10:00:01+0000 host sshd[1]: Accepted password for root\n" +
			"\n" +
			"2026-09-08T10:00:02+0000 host sudo[2]: root : COMMAND=/bin/bash\n")

	j := NewJournaldCollector()
	done := make(chan struct{})
	go func() { j.stream(context.Background(), input, out, seq); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not finish")
	}
	close(out)

	var got []models.LogEvent
	for e := range out {
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events (blank line skipped), got %d", len(got))
	}
	for _, e := range got {
		if e.Source != "journald" {
			t.Errorf("source = %q, want journald", e.Source)
		}
		if e.Hash == "" || len(e.Hash) != 64 {
			t.Errorf("hash not a sha256 hex: %q", e.Hash)
		}
		if e.RawContent == "" {
			t.Error("empty RawContent")
		}
	}
	if got[0].Sequence >= got[1].Sequence {
		t.Errorf("sequence not increasing: %d then %d", got[0].Sequence, got[1].Sequence)
	}
	if !strings.Contains(got[0].RawContent, "Accepted password") {
		t.Errorf("unexpected first line: %q", got[0].RawContent)
	}
}

// stream() must stop promptly when the context is cancelled.
func TestJournaldStreamHonoursContext(t *testing.T) {
	seq, _ := OpenSeqStore(filepath.Join(t.TempDir(), "seq.state"), 100)
	out := make(chan models.LogEvent) // unbuffered: emit will block until we cancel
	ctx, cancel := context.WithCancel(context.Background())
	input := strings.NewReader("2026-09-08T10:00:01+0000 host a: one\n2026-09-08T10:00:02+0000 host b: two\n")

	done := make(chan struct{})
	go func() { NewJournaldCollector().stream(ctx, input, out, seq); close(done) }()

	<-out    // receive the first event
	cancel() // then cancel; the collector must return rather than block forever
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not honour context cancellation")
	}
}
