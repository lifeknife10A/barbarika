package config

import (
	"os"
	"time"
)

// Config holds all operational settings for the Barbarika Go Ingestion Daemon.
type Config struct {
	AgentID           string
	BootID            string
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

	return &Config{
		AgentID:           getEnvOrDefault("AGENT_ID", "primary-srv-01"),
		BootID:            getEnvOrDefault("BOOT_ID", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"),
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
