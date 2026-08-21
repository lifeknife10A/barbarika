package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Event represents a normalized security telemetry event emitted by the agent.
type Event struct {
	EventType   string                 `json:"event_type"`
	Source      string                 `json:"source"`
	Severity    string                 `json:"severity"`
	OccurredAt  string                 `json:"occurred_at"`
	DetectedAt  string                 `json:"detected_at"`
	RawHash     string                 `json:"raw_hash"`
	Sequence    uint64                 `json:"sequence"`
	Payload     map[string]interface{} `json:"payload"`
}

// SignedBatch represents an Ed25519-signed batch of normalized events.
type SignedBatch struct {
	BatchID       string   `json:"batch_id"`
	AgentID       string   `json:"agent_id"`
	SequenceStart uint64   `json:"sequence_start"`
	SequenceEnd   uint64   `json:"sequence_end"`
	EventCount    int      `json:"event_count"`
	Events        []Event  `json:"events"`
	BatchHash     string   `json:"batch_hash"`
	CreatedAt     string   `json:"created_at"`
	PublicKey     string   `json:"public_key"`
	Signature     string   `json:"signature"`
}

// SignedEvent wraps a single normalized event with its Ed25519 signature.
type SignedEvent struct {
	Event     Event  `json:"event"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

var (
	// SSH patterns (/var/log/auth.log)
	reSSHFailPassword = regexp.MustCompile(`(?:Failed|FAILED)\s+(?:password|none)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSSHSuccess      = regexp.MustCompile(`(?:Accepted|ACCEPTED)\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSudoExec        = regexp.MustCompile(`sudo:\s+(\S+)\s+:(?:.*;)?\s*COMMAND=(.*)`)

	// Nginx patterns (/var/log/nginx/access.log)
	reNginxCombined = regexp.MustCompile(`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s"]+)(?:\s+([^"]+))?"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"`)

	// Exploit keywords in URLs
	reExploitPatterns = regexp.MustCompile(`(?i)(/\.env|/\.git|etc/passwd|/wp-admin|\bunion\b|\bselect\b|'|--|<script>|\.\./)`)
)

// Normalizer normalizes raw log lines and system events into standard structured Events.
type Normalizer struct {
	source   string
	sequence uint64
}

// NewNormalizer creates a new Normalizer instance.
func NewNormalizer(source string) *Normalizer {
	if source == "" {
		source = "primary-srv-01"
	}
	return &Normalizer{
		source: source,
	}
}

// NextSequence increments and returns the next monotonic sequence number.
func (n *Normalizer) NextSequence() uint64 {
	return atomic.AddUint64(&n.sequence, 1)
}

// ComputeHash returns the SHA-256 hex digest of the given byte slice.
func ComputeHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Normalize parses a single raw log line and converts it into a structured Event.
func (n *Normalizer) Normalize(rawLine string) Event {
	rawLine = strings.TrimRight(rawLine, "\r\n")
	detectedAt := time.Now().UTC().Format(time.RFC3339Nano)
	seq := n.NextSequence()
	rawHash := ComputeHash([]byte(rawLine))

	// Check if this is a journald JSON line
	if strings.HasPrefix(strings.TrimSpace(rawLine), "{") && strings.HasSuffix(strings.TrimSpace(rawLine), "}") {
		var jmap map[string]interface{}
		if err := json.Unmarshal([]byte(rawLine), &jmap); err == nil {
			return n.normalizeJournaldJSON(jmap, rawLine, rawHash, seq, detectedAt)
		}
	}

	// Base event template
	event := Event{
		EventType:  "raw_log_event",
		Source:     n.source,
		Severity:   "info",
		OccurredAt: detectedAt,
		DetectedAt: detectedAt,
		RawHash:    rawHash,
		Sequence:   seq,
		Payload: map[string]interface{}{
			"raw_message": rawLine,
		},
	}

	// 1. Check SSH Failed Password
	if matches := reSSHFailPassword.FindStringSubmatch(rawLine); len(matches) >= 4 {
		user := matches[1]
		srcIP := matches[2]
		port, _ := strconv.Atoi(matches[3])

		event.EventType = "ssh_auth_failure"
		event.Severity = "warn"
		event.Payload["user"] = user
		event.Payload["src_ip"] = srcIP
		event.Payload["src_port"] = port
		event.Payload["auth_method"] = "password"
		return event
	}

	// 2. Check SSH Accepted / Success
	if matches := reSSHSuccess.FindStringSubmatch(rawLine); len(matches) >= 5 {
		authMethod := matches[1]
		user := matches[2]
		srcIP := matches[3]
		port, _ := strconv.Atoi(matches[4])

		event.EventType = "ssh_auth_success"
		event.Severity = "info"
		event.Payload["auth_method"] = authMethod
		event.Payload["user"] = user
		event.Payload["src_ip"] = srcIP
		event.Payload["src_port"] = port
		return event
	}

	// 3. Check Sudo Execution
	if matches := reSudoExec.FindStringSubmatch(rawLine); len(matches) >= 3 {
		user := matches[1]
		command := strings.TrimSpace(matches[2])

		event.EventType = "sudo_execution"
		event.Severity = "warn"
		event.Payload["user"] = user
		event.Payload["command"] = command
		return event
	}

	// 4. Check Nginx Access Log
	if matches := reNginxCombined.FindStringSubmatch(rawLine); len(matches) >= 10 {
		clientIP := matches[1]
		rawTime := matches[3]
		method := matches[4]
		path := matches[5]
		statusCode, _ := strconv.Atoi(matches[7])
		userAgent := matches[10]

		event.Payload["client_ip"] = clientIP
		event.Payload["method"] = method
		event.Payload["path"] = path
		event.Payload["status_code"] = statusCode
		event.Payload["user_agent"] = userAgent
		event.Payload["log_time"] = rawTime

		if reExploitPatterns.MatchString(path) {
			event.EventType = "http_exploit_pattern"
			event.Severity = "warn"
			event.Payload["is_exploit_probe"] = true
		} else {
			event.EventType = "http_request"
			event.Severity = "info"
		}
		return event
	}

	return event
}

// normalizeJournaldJSON normalizes journalctl -o json structured objects.
func (n *Normalizer) normalizeJournaldJSON(jmap map[string]interface{}, rawLine, rawHash string, seq uint64, detectedAt string) Event {
	occurredAt := detectedAt

	// Extract timestamp if available (__REALTIME_TIMESTAMP is microseconds since epoch)
	if rt, ok := jmap["__REALTIME_TIMESTAMP"].(string); ok {
		if us, err := strconv.ParseInt(rt, 10, 64); err == nil {
			occurredAt = time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
		}
	} else if rtNum, ok := jmap["__REALTIME_TIMESTAMP"].(float64); ok {
		occurredAt = time.UnixMicro(int64(rtNum)).UTC().Format(time.RFC3339Nano)
	}

	msg, _ := jmap["MESSAGE"].(string)
	unit, _ := jmap["_SYSTEMD_UNIT"].(string)

	event := Event{
		EventType:  "journald_log",
		Source:     n.source,
		Severity:   "info",
		OccurredAt: occurredAt,
		DetectedAt: detectedAt,
		RawHash:    rawHash,
		Sequence:   seq,
		Payload: map[string]interface{}{
			"raw_message":  msg,
			"systemd_unit": unit,
			"journal_data": jmap,
		},
	}

	// Correlate message contents
	if strings.Contains(msg, "Failed password") {
		event.EventType = "ssh_auth_failure"
		event.Severity = "warn"
		if matches := reSSHFailPassword.FindStringSubmatch(msg); len(matches) >= 4 {
			event.Payload["user"] = matches[1]
			event.Payload["src_ip"] = matches[2]
			port, _ := strconv.Atoi(matches[3])
			event.Payload["src_port"] = port
			event.Payload["auth_method"] = "password"
		}
	} else if strings.Contains(msg, "Accepted ") {
		event.EventType = "ssh_auth_success"
		if matches := reSSHSuccess.FindStringSubmatch(msg); len(matches) >= 5 {
			event.Payload["auth_method"] = matches[1]
			event.Payload["user"] = matches[2]
			event.Payload["src_ip"] = matches[3]
			port, _ := strconv.Atoi(matches[4])
			event.Payload["src_port"] = port
		}
	} else if strings.Contains(msg, "sudo:") {
		event.EventType = "sudo_execution"
		event.Severity = "warn"
		if matches := reSudoExec.FindStringSubmatch(msg); len(matches) >= 3 {
			event.Payload["user"] = matches[1]
			event.Payload["command"] = strings.TrimSpace(matches[2])
		}
	}

	return event
}

// NormalizeFileEvent converts file-integrity watcher events into normalized Events.
func (n *Normalizer) NormalizeFileEvent(path, op string, isCanary bool, fileHash string) Event {
	detectedAt := time.Now().UTC().Format(time.RFC3339Nano)
	seq := n.NextSequence()

	rawContent := path + ":" + op + ":" + strconv.FormatBool(isCanary) + ":" + fileHash
	rawHash := ComputeHash([]byte(rawContent))

	eventType := "file_change"
	severity := "info"
	if isCanary {
		eventType = "canary_tampered"
		severity = "critical"
	} else if op == "REMOVE" || op == "WRITE" {
		severity = "warn"
	}

	return Event{
		EventType:  eventType,
		Source:     n.source,
		Severity:   severity,
		OccurredAt: detectedAt,
		DetectedAt: detectedAt,
		RawHash:    rawHash,
		Sequence:   seq,
		Payload: map[string]interface{}{
			"path":       path,
			"operation":  op,
			"is_canary":  isCanary,
			"file_hash":  fileHash,
		},
	}
}
