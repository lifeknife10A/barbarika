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

	// 1. Create a normal web file
	testFile := filepath.Join(wwwDir, "index.html")
	if err := os.WriteFile(testFile, []byte("<h1>Hello World</h1>"), 0644); err != nil {
		t.Fatalf("failed to write testFile: %v", err)
	}

	select {
	case evt := <-eventsChan:
		if evt.Payload["is_canary"] == true {
			t.Fatal("expected is_canary=false for www index.html")
		}
		if evt.EventType != "file_change" {
			t.Fatalf("expected file_change, got %s", evt.EventType)
		}
	case err := <-errChan:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for create event")
	}

	// 2. Touch canary file
	canaryFile := filepath.Join(canaryDir, "secret_key.token")
	if err := os.WriteFile(canaryFile, []byte("canary-trap-value"), 0644); err != nil {
		t.Fatalf("failed to write canaryFile: %v", err)
	}

	select {
	case evt := <-eventsChan:
		if evt.Payload["is_canary"] != true {
			t.Fatalf("expected is_canary=true, got %v", evt.Payload["is_canary"])
		}
		if evt.EventType != "canary_tampered" {
			t.Fatalf("expected canary_tampered, got %s", evt.EventType)
		}
		if evt.Severity != "critical" {
			t.Fatalf("expected severity critical, got %s", evt.Severity)
		}
	case err := <-errChan:
		t.Fatalf("watcher error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canary event")
	}
}
