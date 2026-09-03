package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"barbarika-agent/config"
	"barbarika-agent/pkg/crypto"
	"barbarika-agent/pkg/models"
)

// Client handles outbound HTTP/mTLS payload transport to Sentry.
type Client struct {
	cfg        *config.Config
	signer     *crypto.Signer
	httpClient *http.Client
}

// NewClient initializes the egress HTTP client.
func NewClient(cfg *config.Config, signer *crypto.Signer) *Client {
	return &Client{
		cfg:    cfg,
		signer: signer,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SendHeartbeat dispatches a 5-second Watchdog ping payload to Sentry.
func (c *Client) SendHeartbeat(ctx context.Context, payload *models.HeartbeatPayload) error {
	// Serialize payload without signature to calculate Ed25519 signature bytes
	payloadBytes, err := json.Marshal(map[string]interface{}{
		"agent_id":            payload.AgentID,
		"boot_id":             payload.BootID,
		"sequence":            payload.Sequence,
		"sent_at_utc":         payload.SentAtUTC,
		"last_event_sequence": payload.LastEventSequence,
		"last_event_hash":     payload.LastEventHash,
		"agent_health":        payload.AgentHealth,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat for signing: %w", err)
	}

	// Attach Ed25519 signature
	payload.Signature = c.signer.Sign(payloadBytes)

	fullBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal signed heartbeat: %w", err)
	}

	url := fmt.Sprintf("%s/heartbeat", c.cfg.SentryBaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(fullBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.cfg.AgentID)
	req.Header.Set("X-Public-Key", c.signer.PublicKeyBase64())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Heartbeat Warning] Failed to reach Sentry endpoint: %v (Simulating egress)", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[Heartbeat Warning] Sentry returned HTTP status: %d", resp.StatusCode)
	}
	return nil
}

// SendEvent dispatches a single normalized log event to Sentry's POST /events
// endpoint in the schemas.EventIn shape (see integration/CONTRACT.md). The
// agent's own SHA-256 and Ed25519 signature are carried inside `payload` for
// provenance; Sentry computes its own hash chain on top. Unlike the heartbeat
// path, egress errors here are returned (not swallowed) so the caller can log
// a real delivery failure instead of silently dropping evidence.
func (c *Client) SendEvent(ctx context.Context, ev models.LogEvent) error {
	timestamp := ev.Timestamp.UTC().Format(time.RFC3339Nano)

	// Sign the canonical event tuple so the agent identity/authenticity travels
	// with the event even though the current Sentry receiver does not yet verify it.
	signable := fmt.Sprintf("%s|%d|%s|%s|%s", c.cfg.AgentID, ev.Sequence, timestamp, ev.Source, ev.RawContent)
	signature := c.signer.Sign([]byte(signable))

	out := toSentryEvent(c.cfg.AgentID, timestamp, c.signer.PublicKeyBase64(), signature, ev)
	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("failed to marshal event seq %d: %w", ev.Sequence, err)
	}

	url := fmt.Sprintf("%s/events", c.cfg.SentryBaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.cfg.AgentID)
	req.Header.Set("X-Public-Key", c.signer.PublicKeyBase64())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("event egress to Sentry failed (seq %d): %w", ev.Sequence, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("sentry rejected event seq %d: HTTP %d", ev.Sequence, resp.StatusCode)
	}
	return nil
}

// SendEventBatch dispatches a signed log event batch to Sentry.
func (c *Client) SendEventBatch(ctx context.Context, batch *models.EventBatch) error {
	payloadBytes, err := json.Marshal(map[string]interface{}{
		"agent_id":   batch.AgentID,
		"batch_id":   batch.BatchID,
		"count":      batch.Count,
		"events":     batch.Events,
		"batch_hash": batch.BatchHash,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	batch.Signature = c.signer.Sign(payloadBytes)
	fullBytes, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal signed batch: %w", err)
	}

	url := fmt.Sprintf("%s/v1/events", c.cfg.SentryBaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(fullBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.cfg.AgentID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Egress Warning] Failed to send event batch to Sentry: %v", err)
		return nil
	}
	defer resp.Body.Close()

	return nil
}
