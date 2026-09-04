package egress

import (
	"strings"

	"barbarika-agent/pkg/models"
)

// SentryEvent is the exact wire shape Sentry's `POST /ingest` expects
// (sentry/app/models.py :: EventIn). EventIn forbids extra top-level fields, so
// agent provenance (id, sequence, sha256, pubkey, signature) travels in
// `payload`. Sentry assigns the sequence + received_at and seals the content at
// rest. See integration/CONTRACT.md.
type SentryEvent struct {
	EventType  string                 `json:"event_type"`
	Source     string                 `json:"source"`
	Severity   string                 `json:"severity"`
	Category   *string                `json:"category,omitempty"`
	OccurredAt string                 `json:"occurred_at"`
	DetectedAt string                 `json:"detected_at"`
	RawMessage string                 `json:"raw_message"`
	Payload    map[string]interface{} `json:"payload"`
}

// classifyEventType maps a raw log line to the canonical event_type Sentry stores.
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

// candidateCategory tags an event with the CERT-In Annexure I category whose
// rules should evaluate it. Detection confirms an incident within that category
// (see sentry/app/detect.py). Returns nil when no category applies (the event is
// still stored + chained, just not rule-evaluated). Coordinate this map with the
// rules package (Anishka) as new category rules land.
func candidateCategory(eventType string) *string {
	var c string
	switch eventType {
	case "ssh_failed_login", "ssh_login", "sudo_exec":
		c = "iii" // Unauthorised access of IT systems/data
	default:
		return nil
	}
	return &c
}

// severityFor gives Sentry a coarse severity per event_type.
func severityFor(eventType string) string {
	switch eventType {
	case "ssh_login", "sudo_exec":
		return "critical"
	case "ssh_failed_login", "http_request":
		return "warn"
	default:
		return "info"
	}
}

// toSentryEvent maps a collected LogEvent into Sentry's EventIn wire shape,
// preserving the agent's SHA-256 + Ed25519 signature inside `payload` for
// receive-side verification and provenance.
func toSentryEvent(agentID, timestamp, pubKey, signature string, ev models.LogEvent) SentryEvent {
	eventType := classifyEventType(ev.Source, ev.RawContent)
	return SentryEvent{
		EventType:  eventType,
		Source:     agentID + "/" + ev.Source,
		Severity:   severityFor(eventType),
		Category:   candidateCategory(eventType),
		OccurredAt: timestamp,
		DetectedAt: timestamp,
		RawMessage: ev.RawContent,
		Payload: map[string]interface{}{
			"agent_id":        agentID,
			"agent_sequence":  ev.Sequence,
			"agent_sha256":    ev.Hash,
			"agent_pubkey":    pubKey,
			"agent_signature": signature,
		},
	}
}
