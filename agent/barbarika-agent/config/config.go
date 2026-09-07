package config

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
)

// Config holds all operational settings for the Barbarika Go Ingestion Daemon.
type Config struct {
	AgentID           string
	BootID            string
	AgentKeyPath      string
	SeqStatePath      string
	SentryBaseURL     string
	HeartbeatInterval time.Duration
	BatchFlushTimeout time.Duration
	MaxBatchSize      int
	LogSources        map[string]string

	// mTLS transport (Jash's transport/ material). When SentryBaseURL is https,
	// CACertPath verifies Sentry's server certificate and ClientCert/KeyPath
	// present the agent's client identity for mutual auth. Empty => plaintext.
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
}

// LoadConfig initializes agent settings with sensible defaults and environment overrides.
func LoadConfig() *Config {
	// Detect OS for default log paths (local mock for Windows, system paths for Linux)
	authLogPath := "./mock_logs/auth.log"
	nginxLogPath := "./mock_logs/nginx_access.log"

	if os.Getenv("ENV") == "production" || isLinux() {
		authLogPath = "/var/log/auth.log"
		nginxLogPath = "/var/log/nginx/access.log"
	}

	// A fresh boot_id per process start (unless pinned via env) so an agent
	// restart is distinguishable — the heartbeat carries it, and it lets a
	// receiver tell one boot's chain segment from another.
	bootID := os.Getenv("BOOT_ID")
	if bootID == "" {
		bootID = newBootID()
	}

	return &Config{
		AgentID:           getEnvOrDefault("AGENT_ID", "primary-srv-01"),
		BootID:            bootID,
		AgentKeyPath:      getEnvOrDefault("AGENT_KEY_PATH", "./agent_ed25519.key"),
		SeqStatePath:      getEnvOrDefault("AGENT_SEQ_PATH", "./agent_seq.state"),
		SentryBaseURL:     getEnvOrDefault("SENTRY_URL", "http://localhost:8000"),
		HeartbeatInterval: 5 * time.Second,
		BatchFlushTimeout: 2 * time.Second,
		MaxBatchSize:      50,
		LogSources: map[string]string{
			"auth":  authLogPath,
			"nginx": nginxLogPath,
		},
		CACertPath:     os.Getenv("SENTRY_CA_CERT"),
		ClientCertPath: os.Getenv("SENTRY_CLIENT_CERT"),
		ClientKeyPath:  os.Getenv("SENTRY_CLIENT_KEY"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func isLinux() bool {
	return os.Getenv("GOOS") == "linux"
}

// newBootID returns a random RFC 4122 v4 UUID string (schema-valid boot_id).
func newBootID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to a fixed but valid UUID.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
