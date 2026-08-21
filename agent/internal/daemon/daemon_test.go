package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"barbarika/agent/internal/normalizer"
	"barbarika/agent/internal/signer"
	"barbarika/agent/internal/spool"
)

func TestFullDaemonIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	authLog := filepath.Join(tmpDir, "auth.log")
	spoolDir := filepath.Join(tmpDir, "spool")
	watchDir := filepath.Join(tmpDir, "www")
	canaryDir := filepath.Join(tmpDir, "canary")

	_ = os.MkdirAll(watchDir, 0755)
	_ = os.MkdirAll(canaryDir, 0755)

	initialLogs := "Aug 22 01:30:00 srv sshd[1000]: Failed password for invalid user admin from 1.2.3.4 port 1234 ssh2\n"
	_ = os.WriteFile(authLog, []byte(initialLogs), 0644)

	sig, err := signer.NewSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	norm := normalizer.NewNormalizer("primary-srv-01")
	sp, err := spool.NewSpool(spoolDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}

	var outBuf bytes.Buffer
	d := NewDaemon(Config{
		SourceID:     "primary-srv-01",
		AuthLogPath:  authLog,
		WatchDirs:    []string{watchDir},
		CanaryDir:    canaryDir,
		SpoolDir:     spoolDir,
		BatchSize:    2,
		FlushPeriod:  100 * time.Millisecond,
		Follow:       false,
		EmitBatches:  true,
	}, sig, norm, sp, &outBuf)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Ingest a second event directly to complete the batch of 2
	go func() {
		time.Sleep(50 * time.Millisecond)
		d.IngestRawLine("Aug 22 01:30:05 srv sudo:   admin : TTY=pts/0 ; COMMAND=/usr/bin/id")
	}()

	_ = d.Run(ctx)

	output := strings.TrimSpace(outBuf.String())
	if output == "" {
		t.Fatal("expected batch output from daemon, got empty string")
	}

	var batch normalizer.SignedBatch
	if err := json.Unmarshal([]byte(strings.Split(output, "\n")[0]), &batch); err != nil {
		t.Fatalf("failed to unmarshal signed batch: %v", err)
	}

	if batch.EventCount < 1 {
		t.Fatalf("expected at least 1 event in batch, got %d", batch.EventCount)
	}

	// Verify batch signature
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
		t.Fatalf("batch signature failed verification: %v", err)
	}
}
