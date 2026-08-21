package batcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"barbarika/agent/internal/normalizer"
	"barbarika/agent/internal/signer"
)

// Config holds configuration for the event batcher.
type Config struct {
	AgentID       string
	MaxBatchSize  int
	FlushInterval time.Duration
}

// Batcher accumulates events in memory and emits Ed25519-signed batches.
type Batcher struct {
	cfg        Config
	signer     *signer.Signer
	mu         sync.Mutex
	pending    []normalizer.Event
	batchCount uint64
	outChan    chan normalizer.SignedBatch
}

// NewBatcher creates a new Batcher.
func NewBatcher(cfg Config, sig *signer.Signer) *Batcher {
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 500 * time.Millisecond
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "primary-srv-01"
	}

	return &Batcher{
		cfg:     cfg,
		signer:  sig,
		outChan: make(chan normalizer.SignedBatch, 20),
	}
}

// OutChannel returns the channel where signed batches are emitted.
func (b *Batcher) OutChannel() <-chan normalizer.SignedBatch {
	return b.outChan
}

// Add adds an event to the batcher. If batch size is reached, it flushes automatically.
func (b *Batcher) Add(evt normalizer.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pending = append(b.pending, evt)
	if len(b.pending) >= b.cfg.MaxBatchSize {
		b.flushLocked()
	}
}

// Flush manually triggers an immediate flush of any pending events.
func (b *Batcher) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

// Start runs the periodic flush timer until ctx is cancelled.
func (b *Batcher) Start(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Flush()
			return
		case <-ticker.C:
			b.Flush()
		}
	}
}

// flushLocked seals the current batch, computes its cryptographic batch hash, signs it, and emits.
func (b *Batcher) flushLocked() {
	if len(b.pending) == 0 {
		return
	}

	batchNum := atomic.AddUint64(&b.batchCount, 1)
	batchID := fmt.Sprintf("batch-%s-%d-%d", b.cfg.AgentID, time.Now().Unix(), batchNum)

	seqStart := b.pending[0].Sequence
	seqEnd := b.pending[len(b.pending)-1].Sequence

	// Compute Batch Hash: SHA-256 of all event raw hashes concatenated
	hasher := sha256.New()
	for _, e := range b.pending {
		hasher.Write([]byte(e.RawHash))
		hasher.Write([]byte(e.DetectedAt))
	}
	batchHash := hex.EncodeToString(hasher.Sum(nil))

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	// Build summary struct for signature
	sigSummary := struct {
		BatchID    string `json:"batch_id"`
		AgentID    string `json:"agent_id"`
		BatchHash  string `json:"batch_hash"`
		EventCount int    `json:"event_count"`
		CreatedAt  string `json:"created_at"`
	}{
		BatchID:    batchID,
		AgentID:    b.cfg.AgentID,
		BatchHash:  batchHash,
		EventCount: len(b.pending),
		CreatedAt:  createdAt,
	}

	sigBytes, _ := json.Marshal(sigSummary)
	signature := b.signer.SignBase64(sigBytes)

	batch := normalizer.SignedBatch{
		BatchID:       batchID,
		AgentID:       b.cfg.AgentID,
		SequenceStart: seqStart,
		SequenceEnd:   seqEnd,
		EventCount:    len(b.pending),
		Events:        b.pending,
		BatchHash:     batchHash,
		CreatedAt:     createdAt,
		PublicKey:     b.signer.PublicKeyBase64(),
		Signature:     signature,
	}

	b.pending = nil
	select {
	case b.outChan <- batch:
	default:
		// Drop or buffer if consumer saturated
	}
}
