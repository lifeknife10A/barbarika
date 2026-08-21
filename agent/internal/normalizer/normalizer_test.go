package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNormalizerSSHAuthFailure(t *testing.T) {
	n := NewNormalizer("test-host")
	raw := "Aug 22 01:05:10 ubuntu sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 45231 ssh2"

	evt := n.Normalize(raw)

	if evt.EventType != "ssh_auth_failure" {
		t.Fatalf("expected event_type 'ssh_auth_failure', got '%s'", evt.EventType)
	}
	if evt.Severity != "warn" {
		t.Fatalf("expected severity 'warn', got '%s'", evt.Severity)
	}
	if evt.Source != "test-host" {
		t.Fatalf("expected source 'test-host', got '%s'", evt.Source)
	}
	if evt.Sequence != 1 {
		t.Fatalf("expected sequence 1, got %d", evt.Sequence)
	}
	if evt.Payload["user"] != "admin" {
		t.Fatalf("expected user 'admin', got '%v'", evt.Payload["user"])
	}
	if evt.Payload["src_ip"] != "192.168.1.105" {
		t.Fatalf("expected src_ip '192.168.1.105', got '%v'", evt.Payload["src_ip"])
	}

	// Verify SHA-256 hash
	hasher := sha256.New()
	hasher.Write([]byte(raw))
	expectedHash := hex.EncodeToString(hasher.Sum(nil))
	if evt.RawHash != expectedHash {
		t.Fatalf("expected hash %s, got %s", expectedHash, evt.RawHash)
	}
}

func TestNormalizerSSHAuthSuccess(t *testing.T) {
	n := NewNormalizer("test-host")
	raw := "Aug 22 01:06:00 ubuntu sshd[1250]: Accepted publickey for ubuntu from 192.168.1.50 port 55122 ssh2"

	evt := n.Normalize(raw)

	if evt.EventType != "ssh_auth_success" {
		t.Fatalf("expected event_type 'ssh_auth_success', got '%s'", evt.EventType)
	}
	if evt.Severity != "info" {
		t.Fatalf("expected severity 'info', got '%s'", evt.Severity)
	}
	if evt.Payload["user"] != "ubuntu" {
		t.Fatalf("expected user 'ubuntu', got '%v'", evt.Payload["user"])
	}
}

func TestNormalizerSudoExecution(t *testing.T) {
	n := NewNormalizer("test-host")
	raw := "Aug 22 01:06:15 ubuntu sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"

	evt := n.Normalize(raw)

	if evt.EventType != "sudo_execution" {
		t.Fatalf("expected event_type 'sudo_execution', got '%s'", evt.EventType)
	}
	if evt.Payload["command"] != "/usr/bin/cat /etc/shadow" {
		t.Fatalf("expected command '/usr/bin/cat /etc/shadow', got '%v'", evt.Payload["command"])
	}
}

func TestNormalizerNginxExploitProbe(t *testing.T) {
	n := NewNormalizer("test-host")
	raw := `192.168.1.200 - - [22/Aug/2026:01:07:00 +0000] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.6"`

	evt := n.Normalize(raw)

	if evt.EventType != "http_exploit_pattern" {
		t.Fatalf("expected event_type 'http_exploit_pattern', got '%s'", evt.EventType)
	}
	if evt.Severity != "warn" {
		t.Fatalf("expected severity 'warn', got '%s'", evt.Severity)
	}
	if evt.Payload["path"] != "/.env" {
		t.Fatalf("expected path '/.env', got '%v'", evt.Payload["path"])
	}
	if evt.Payload["status_code"] != 404 {
		t.Fatalf("expected status_code 404, got '%v'", evt.Payload["status_code"])
	}
}

func TestNormalizerGenericFallback(t *testing.T) {
	n := NewNormalizer("test-host")
	raw := "Aug 22 01:08:00 ubuntu systemd[1]: Started User Manager for UID 1000."

	evt := n.Normalize(raw)

	if evt.EventType != "raw_log_event" {
		t.Fatalf("expected event_type 'raw_log_event', got '%s'", evt.EventType)
	}
	if evt.Payload["raw_message"] != raw {
		t.Fatalf("expected raw_message matching raw input, got '%v'", evt.Payload["raw_message"])
	}
}

func TestNormalizerJournaldJSON(t *testing.T) {
	n := NewNormalizer("test-host")
	jline := `{"__REALTIME_TIMESTAMP":"1724283900000000","MESSAGE":"sshd[500]: Failed password for root from 10.10.10.10 port 44332 ssh2","_SYSTEMD_UNIT":"ssh.service"}`

	evt := n.Normalize(jline)
	if evt.EventType != "ssh_auth_failure" {
		t.Fatalf("expected event_type 'ssh_auth_failure', got '%s'", evt.EventType)
	}
	if evt.Payload["user"] != "root" {
		t.Fatalf("expected user 'root', got '%v'", evt.Payload["user"])
	}
	if evt.Payload["systemd_unit"] != "ssh.service" {
		t.Fatalf("expected systemd_unit 'ssh.service', got '%v'", evt.Payload["systemd_unit"])
	}
}

func TestNormalizerFileEvent(t *testing.T) {
	n := NewNormalizer("test-host")
	evt := n.NormalizeFileEvent("/var/www/html/index.php", "WRITE", false, "abcdef123456")

	if evt.EventType != "file_change" {
		t.Fatalf("expected event_type 'file_change', got '%s'", evt.EventType)
	}
	if evt.Payload["path"] != "/var/www/html/index.php" {
		t.Fatalf("expected path match, got '%v'", evt.Payload["path"])
	}

	canaryEvt := n.NormalizeFileEvent("/var/canary/.lock", "REMOVE", true, "")
	if canaryEvt.EventType != "canary_tampered" {
		t.Fatalf("expected canary_tampered, got '%s'", canaryEvt.EventType)
	}
	if canaryEvt.Severity != "critical" {
		t.Fatalf("expected severity 'critical', got '%s'", canaryEvt.Severity)
	}
}
