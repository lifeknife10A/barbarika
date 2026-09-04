package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"barbarika-agent/pkg/models"
)

// drainFor collects FIM events for up to d, returning the first whose RawContent
// satisfies pred (or nil on timeout). fsnotify batching/order is nondeterministic,
// so match on a predicate rather than a fixed position.
func drainFor(ch <-chan models.LogEvent, d time.Duration, pred func(string) bool) *models.LogEvent {
	deadline := time.After(d)
	for {
		select {
		case ev := <-ch:
			if ev.Source == "fim" && pred(ev.RawContent) {
				e := ev
				return &e
			}
		case <-deadline:
			return nil
		}
	}
}

func TestFIMWatcherEmitsWireFormat(t *testing.T) {
	tmp := t.TempDir()
	web := filepath.Join(tmp, "www")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	seq, err := OpenSeqStore(filepath.Join(tmp, "seq.state"), 100)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewFIMWatcher([]string{web}, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan models.LogEvent, 64)
	w.Start(ctx, out, seq)
	time.Sleep(100 * time.Millisecond) // let the watch register

	// A normal web-root write -> "FIM <OP> <path> sha256=<hex>".
	target := filepath.Join(web, "index.php")
	if err := os.WriteFile(target, []byte("<?php echo 'defaced'; ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := drainFor(out, 3*time.Second, func(raw string) bool {
		return strings.Contains(raw, target)
	})
	if ev == nil {
		t.Fatal("no FIM event for the web-root write")
	}
	f := strings.Fields(ev.RawContent)
	if f[0] != "FIM" {
		t.Fatalf("raw does not start with FIM: %q", ev.RawContent)
	}
	if op := f[1]; op != "CREATE" && op != "WRITE" {
		t.Fatalf("unexpected op %q in %q", op, ev.RawContent)
	}
	last := f[len(f)-1]
	if !strings.HasPrefix(last, "sha256=") || last == "sha256=" || last == "sha256=-" {
		t.Fatalf("expected a real content hash, got %q", last)
	}
	if ev.Hash == "" {
		t.Fatal("event hash not computed")
	}

	// A canary file -> "FIM CANARY <OP> <path> sha256=...".
	canary := filepath.Join(web, ".canary_token.docx")
	if err := os.WriteFile(canary, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}
	cev := drainFor(out, 3*time.Second, func(raw string) bool {
		return strings.Contains(raw, canary)
	})
	if cev == nil {
		t.Fatal("no FIM event for the canary write")
	}
	if !strings.HasPrefix(cev.RawContent, "FIM CANARY ") {
		t.Fatalf("canary event missing CANARY marker: %q", cev.RawContent)
	}
}
