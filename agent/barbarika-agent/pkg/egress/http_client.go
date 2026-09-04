package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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

// NewClient initializes the egress HTTP client, building a TLS 1.3 mutual-auth
// transport when SentryBaseURL is https (using Jash's transport/ certs).
func NewClient(cfg *config.Config, signer *crypto.Signer) (*Client, error) {
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:        cfg,
		signer:     signer,
		httpClient: httpClient,
	}, nil
}

// newHTTPClient returns a plaintext client for http:// targets, or a TLS 1.3
// mutual-auth client for https:// targets. The custom transport has no proxy,
// so the agent connects directly to the isolated Sentry host (outbound-only).
func newHTTPClient(cfg *config.Config) (*http.Client, error) {
	timeout := 5 * time.Second
	if !strings.HasPrefix(strings.ToLower(cfg.SentryBaseURL), "https") {
		return &http.Client{Timeout: timeout}, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if cfg.CACertPath != "" {
		caPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificate in CA file %s", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
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

// SendEvent dispatches a single normalized log event to Sentry's POST /ingest
// endpoint in the EventIn shape (see integration/CONTRACT.md). Sentry assigns the
// sequence + received_at, seals the content at rest, masks reads, and evaluates
// detection rules. The agent's Ed25519 signature (over the exact wire fields) and
// SHA-256 travel inside `payload` for receive-side verification. Egress errors
// are returned (not swallowed) so the caller can log a real delivery failure.
func (c *Client) SendEvent(ctx context.Context, ev models.LogEvent) error {
	timestamp := ev.Timestamp.UTC().Format(time.RFC3339Nano)
	source := c.cfg.AgentID + "/" + ev.Source
	eventType := classifyEventType(ev.Source, ev.RawContent)
	severity := severityFor(eventType)
	category := ""
	if cat := candidateCategory(eventType, ev.RawContent); cat != nil {
		category = *cat
	}

	// Sign over the full canonical logical event Sentry receives (occurred_at ==
	// detected_at on egress), so the receiver can reconstruct the preimage from
	// the raw request and verify every security-relevant field (see the CONTRACT).
	signable := canonicalSignable(eventType, source, severity, category, timestamp, timestamp, ev.RawContent, ev.Hash)
	signature := c.signer.Sign([]byte(signable))

	out := toSentryEvent(c.cfg.AgentID, timestamp, c.signer.PublicKeyBase64(), signature, ev)
	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("failed to marshal event seq %d: %w", ev.Sequence, err)
	}

	url := fmt.Sprintf("%s/ingest", c.cfg.SentryBaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

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
