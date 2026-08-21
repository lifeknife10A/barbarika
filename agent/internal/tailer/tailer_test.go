package tailer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTailerStaticFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	content := "Line 1: auth success\nLine 2: ssh failed\nLine 3: sudo command\n"
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	tail := NewTailer(Config{
		FilePath:      logPath,
		Follow:        false,
		FromBeginning: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	linesChan, errChan := tail.Start(ctx)

	var collected []string
	for line := range linesChan {
		collected = append(collected, strings.TrimRight(line, "\r\n"))
	}

	if err := <-errChan; err != nil {
		t.Fatalf("tailer returned unexpected error: %v", err)
	}

	if len(collected) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(collected), collected)
	}
	if collected[0] != "Line 1: auth success" || collected[1] != "Line 2: ssh failed" || collected[2] != "Line 3: sudo command" {
		t.Fatalf("mismatched lines: %v", collected)
	}
}

func TestTailerFollowMode(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "follow.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create follow log: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString("Initial line 1\n"); err != nil {
		t.Fatalf("failed to write initial line: %v", err)
	}

	tail := NewTailer(Config{
		FilePath:      logPath,
		Follow:        true,
		PollInterval:  20 * time.Millisecond,
		FromBeginning: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	linesChan, _ := tail.Start(ctx)

	// Read initial line
	select {
	case line := <-linesChan:
		if strings.TrimSpace(line) != "Initial line 1" {
			t.Fatalf("expected 'Initial line 1', got '%s'", line)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for initial line")
	}

	// Append dynamic line
	if _, err := f.WriteString("Dynamic line 2\n"); err != nil {
		t.Fatalf("failed to write dynamic line: %v", err)
	}

	select {
	case line := <-linesChan:
		if strings.TrimSpace(line) != "Dynamic line 2" {
			t.Fatalf("expected 'Dynamic line 2', got '%s'", line)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for dynamic line")
	}
}
