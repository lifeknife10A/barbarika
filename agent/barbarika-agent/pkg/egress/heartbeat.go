package egress

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"barbarika-agent/config"
	"barbarika-agent/pkg/models"
)

// zeroHash is the last_event_hash sent before any event has been observed. Jash's
// transport/heartbeat.schema.json requires a 64-char lowercase hex digest, so an
// empty string would be rejected; the all-zero digest is the documented sentinel.
var zeroHash = strings.Repeat("0", 64)

// HeartbeatWatcher runs a 5-second ticker loop for system Watchdog telemetry.
type HeartbeatWatcher struct {
	cfg        *config.Config
	client     *Client
	hbSeq      uint64
	LastSeq    uint64
	LastHash   string
}

// NewHeartbeatWatcher initializes the Watchdog ticker module.
func NewHeartbeatWatcher(cfg *config.Config, client *Client) *HeartbeatWatcher {
	return &HeartbeatWatcher{
		cfg:      cfg,
		client:   client,
		LastHash: zeroHash, // schema-valid until the first event is observed
	}
}

// Start launches the 5-second heartbeat ticker loop in a background goroutine.
func (hw *HeartbeatWatcher) Start(ctx context.Context) {
	ticker := time.NewTicker(hw.cfg.HeartbeatInterval)
	defer ticker.Stop()

	log.Printf("[Heartbeat] Initialized 5-second Watchdog ticker loop (Agent ID: %s)", hw.cfg.AgentID)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Heartbeat] Stopping Watchdog ticker loop.")
			return
		case <-ticker.C:
			seq := atomic.AddUint64(&hw.hbSeq, 1)

			payload := &models.HeartbeatPayload{
				AgentID:           hw.cfg.AgentID,
				BootID:            hw.cfg.BootID,
				Sequence:          seq,
				SentAtUTC:         time.Now().UTC().Format(time.RFC3339),
				LastEventSequence: hw.LastSeq,
				LastEventHash:     hw.LastHash,
				AgentHealth:       "healthy",
			}

			log.Printf("[Heartbeat Ping #%d] Sent at %s | Last Event Seq: %d | Signature: [ed25519]",
				payload.Sequence, payload.SentAtUTC, payload.LastEventSequence)

			_ = hw.client.SendHeartbeat(ctx, payload)
		}
	}
}
