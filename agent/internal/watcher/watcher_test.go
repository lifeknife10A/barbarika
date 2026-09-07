package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"barbarika/agent/internal/normalizer"
)

func TestWatcherFileEvents(t *testing.T) {
	tmpDir := t.TempDir()
	wwwDir := filepath.Join(tmpDir, "www")
	canaryDir := filepath.Join(tmpDir, "canary")

	if err := os.MkdirAll(wwwDir, 0755); err != nil {
		t.Fatalf("failed to create wwwDir: %v", err)
	}
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		t.Fatalf("failed to create canaryDir: %v", err)
	}

	norm := normalizer.NewNormalizer("test-agent")
	w, err := NewWatcher(Config{
		WatchDirs: []string{wwwDir},
		CanaryDir: canaryDir,
	}, norm)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan, errChan, err := w.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start watcher: %v", err)
	}

	// Allow watcher to initialize
	time.Sleep(100 * time.Millisecond)

	// 1. Create a normal web file. A single write can surface as a CREATE and
	//    then a WRITE, so match the first non-canary event rather than assuming
	//    exactly one event arrives.
	testFile := filepath.Join(wwwDir, "index.html")
	if err := os.WriteFile(testFile, []byte("<h1>Hello World</h1>"), 0644); err != nil {
		t.Fatalf("failed to write testFile: %v", err)
	}

	wwwEvt := receiveEventWhere(t, eventsChan, errChan, 2*time.Second, func(evt normalizer.Event) bool {
		return evt.Payload["is_canary"] != true
	})
	if wwwEvt.EventType != "file_change" {
		t.Fatalf("expected file_change, got %s", wwwEvt.EventType)
	}

	// 2. Touch the canary file. Drain any leftover www events (e.g. a paired
	//    WRITE for index.html) by matching on the canary signal specifically.
	canaryFile := filepath.Join(canaryDir, "secret_key.token")
	if err := os.WriteFile(canaryFile, []byte("canary-trap-value"), 0644); err != nil {
		t.Fatalf("failed to write canaryFile: %v", err)
	}

	canaryEvt := receiveEventWhere(t, eventsChan, errChan, 2*time.Second, func(evt normalizer.Event) bool {
		return evt.Payload["is_canary"] == true
	})
	if canaryEvt.EventType != "canary_tampered" {
		t.Fatalf("expected canary_tampered, got %s", canaryEvt.EventType)
	}
	if canaryEvt.Severity != "critical" {
		t.Fatalf("expected severity critical, got %s", canaryEvt.Severity)
	}
}

// receiveEventWhere returns the first event satisfying pred, skipping others
// (a single filesystem write can surface as more than one fsnotify event), or
// fails the test if none arrives within timeout.
func receiveEventWhere(
	t *testing.T,
	eventsChan <-chan normalizer.Event,
	errChan <-chan error,
	timeout time.Duration,
	pred func(normalizer.Event) bool,
) normalizer.Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case evt, ok := <-eventsChan:
			if !ok {
				t.Fatal("events channel closed before a matching event")
			}
			if pred(evt) {
				return evt
			}
		case err := <-errChan:
			t.Fatalf("watcher error: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for a matching file event")
		}
	}
}
