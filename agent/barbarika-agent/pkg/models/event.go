package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// LogEvent represents a single normalized log line harvested from system files.
type LogEvent struct {
	Sequence   uint64    `json:"sequence"`
	Source     string    `json:"source"`     // e.g. "auth", "nginx", "journald"
	Timestamp  time.Time `json:"timestamp"`  // RFC3339 formatted UTC timestamp
	RawContent string    `json:"raw_content"`// Exact raw log payload
	Hash       string    `json:"hash"`       // SHA-256 of (Sequence + Timestamp + RawContent)
}

// ComputeHash calculates the cryptographic SHA-256 digest of the log event.
func (e *LogEvent) ComputeHash() string {
	data := fmt.Sprintf("%d|%s|%s", e.Sequence, e.Timestamp.Format(time.RFC3339Nano), e.RawContent)
	sum := sha256.Sum256([]byte(data))
	e.Hash = hex.EncodeToString(sum[:])
	return e.Hash
}

// EventBatch represents a list of normalized log events sent together to Sentry.
type EventBatch struct {
	AgentID   string     `json:"agent_id"`
	BatchID   string     `json:"batch_id"`
	Count     int        `json:"count"`
	Events    []LogEvent `json:"events"`
	BatchHash string     `json:"batch_hash"` // SHA-256 over concatenated event hashes
	Signature string     `json:"signature"`  // Base64 encoded Ed25519 signature
}

// HeartbeatPayload matches the required 5-second Watchdog specification.
type HeartbeatPayload struct {
	AgentID           string `json:"agent_id"`
	BootID            string `json:"boot_id"`
	Sequence          uint64 `json:"sequence"`
	SentAtUTC         string `json:"sent_at_utc"`
	LastEventSequence uint64 `json:"last_event_sequence"`
	LastEventHash     string `json:"last_event_hash"`
	AgentHealth       string `json:"agent_health"`
	Signature         string `json:"signature"` // Base64 encoded Ed25519 signature
}
