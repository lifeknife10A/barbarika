package egress

import (
	"strings"

	"barbarika-agent/pkg/models"
)

// SentryEvent is the exact wire shape Sentry's `POST /events` expects
// (SentryP/backend/app/schemas.py :: EventIn). This is the integration contract
// between the agent (sender) and Sentry (receiver); see integration/CONTRACT.md.
type SentryEvent struct {
	AgentID   string                 `json:"agent_id"`
	Sequence  uint64                 `json:"sequence"`
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	EventType string                 `json:"event_type"`
	Payload   map[string]interface{} `json:"payload"`
}

// classifyEventType maps a raw log line to the canonical event_type Sentry
// stores. Kept intentionally small — this is a joining-layer convenience so
// Sentry's required `event_type` field is meaningful, not a replacement for the
// richer normalizer in the main agent tree.
func classifyEventType(source, raw string) string {
	r := strings.ToLower(raw)
	switch {
	case strings.Contains(r, "failed password"), strings.Contains(r, "authentication failure"):
		return "ssh_failed_login"
	case strings.Contains(r, "accepted password"), strings.Contains(r, "accepted publickey"):
		return "ssh_login"
	case strings.Contains(r, "sudo:"):
		return "sudo_exec"
	case source == "nginx", strings.Contains(raw, "HTTP/"):
		return "http_request"
	default:
		return "raw_log"
	}
}

// toSentryEvent maps a collected LogEvent into the Sentry wire shape, preserving
// the agent's own SHA-256 and Ed25519 signature inside `payload` for provenance.
// Sentry computes its own hash chain on top of this; the agent-side proofs travel
// alongside so signature verification can be added on the receive side later.
func toSentryEvent(agentID, timestamp, pubKey, signature string, ev models.LogEvent) SentryEvent {
	return SentryEvent{
		AgentID:   agentID,
		Sequence:  ev.Sequence,
		Timestamp: timestamp,
		Source:    ev.Source,
		EventType: classifyEventType(ev.Source, ev.RawContent),
		Payload: map[string]interface{}{
			"raw_content":     ev.RawContent,
			"agent_sha256":    ev.Hash,
			"agent_pubkey":    pubKey,
			"agent_signature": signature,
		},
	}
}
