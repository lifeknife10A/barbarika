package egress

import (
	"regexp"
	"strings"

	"barbarika-agent/pkg/models"
)

// Routing signatures for HTTP-request events. These decide which CERT-In
// category *bucket* an nginx line is sent to; the authoritative match that
// actually fires an incident is the rule regex in rules/rules/v1 (Anishka).
// Kept deliberately close to those rules' signature sets (see
// rules/TELEMETRY_CONTRACT.md §2–§3). Over-tagging a benign line is harmless
// (the rule re-checks and won't fire); the goal is not to *miss* an attack line.
var (
	// Category (x) — unambiguous application-layer exploitation in one request:
	// SQLi (UNION SELECT / tautology), traversal / local-file disclosure, source
	// or secret disclosure (.git/.svn/.env), command injection, DB probing, or a
	// known offensive scanner user-agent.
	reCatX = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`union(?:\s|\+|%20|/\*\*/)+(?:all(?:\s|\+|%20)+)?select`,
		`(?:'|%27)(?:\s|\+|%20)*(?:or|and)(?:\s|\+|%20)`,
		`\bor(?:\s|\+|%20)+1\s*(?:=|%3d)\s*1\b`,
		`/etc/passwd\b`,
		`(?:\.\./|%2e%2e%2f){2,}`,
		`/\.git/`, `/\.svn/`, `/\.env(?:\b|$)`,
		`\binformation_schema\b`, `\bxp_cmdshell\b`,
		`;\s*(?:id|whoami|uname|cat\s+/etc/|curl\s|wget\s|nc\s|bash\s)`,
		`\|\s*(?:id|whoami)\b`,
		`\$\([^)]+\)`,
		`\b(?:sqlmap|nikto|nuclei|wpscan|masscan|acunetix)\b`,
	}, "|"))

	// Category (iv) arm A — defacement-oriented web request (admin/config probe,
	// webshell upload, traversal). Only reached when the line is NOT already a
	// Category (x) match (x wins ties — see candidateCategory).
	reCatIV = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`/wp-login\.php`, `/wp-admin/`, `/xmlrpc\.php`, `/administrator/`, `/wp-config\.php`,
		`/\.env(?:\b|$)`, `/\.git/`,
		`/(?:shell|c99|r57|wso|cmd|up|upload)\w*\.php\b`,
		`/uploads?/[^"\s]*\.ph(?:p|tml)\b`,
		`(?:\.\./){2,}`,
	}, "|"))
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

// canonicalSignable builds the exact byte string the agent signs and Sentry
// re-derives (sentry/app/signatures.py :: canonical_preimage). It covers every
// security-relevant field — event_type, source, severity, category, both
// timestamps, the raw message, and the SHA-256 provenance hash — so a
// man-in-the-middle cannot strip the category (suppressing rule evaluation),
// downgrade the severity, or swap the hash while the signature still verifies.
// A nil/empty category serializes as "" (matching Python's None -> ""). The
// field order and "|" separator MUST stay byte-for-byte identical on both sides.
func canonicalSignable(eventType, source, severity, category, occurredAt, detectedAt, rawMessage, sha256 string) string {
	return strings.Join([]string{
		eventType, source, severity, category,
		occurredAt, detectedAt, rawMessage, sha256,
	}, "|")
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
// rules package (Anishka, rules/TELEMETRY_CONTRACT.md) as new category rules land.
//
// For http_request the category depends on the request line, not just the type:
// an app-layer exploit routes to (x) and a defacement-oriented probe to (iv),
// with (x) winning ties (app-layer exploitation is the stronger claim).
func candidateCategory(eventType, raw string) *string {
	switch eventType {
	case "ssh_failed_login", "ssh_login", "sudo_exec":
		return strptr("iii") // Unauthorised access of IT systems/data
	case "http_request":
		switch {
		case reCatX.MatchString(raw):
			return strptr("x") // Attacks on applications (app-layer exploitation)
		case reCatIV.MatchString(raw):
			return strptr("iv") // Website intrusion / defacement (arm A; needs a FIM event too)
		default:
			return nil
		}
	default:
		return nil
	}
}

func strptr(s string) *string { return &s }

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
		Category:   candidateCategory(eventType, ev.RawContent),
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
