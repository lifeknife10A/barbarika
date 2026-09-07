package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"barbarika-agent/config"
	"barbarika-agent/pkg/collector"
	"barbarika-agent/pkg/crypto"
	"barbarika-agent/pkg/egress"
	"barbarika-agent/pkg/hostmetrics"
)

const agentVersion = "barbarika-agent/0.4"

func main() {
	fmt.Println("=================================================================")
	fmt.Println("  BARBARIKA — Systems Ingestion Daemon & Evidence Engine (Go)  ")
	fmt.Println("=================================================================")

	// 1. Load configuration
	cfg := config.LoadConfig()
	log.Printf("[Config] Agent ID: %s | Boot ID: %s | Sentry Endpoint: %s", cfg.AgentID, cfg.BootID, cfg.SentryBaseURL)

	// 2. Initialize Ed25519 Signer (stable key persisted at cfg.AgentKeyPath so
	//    Sentry can pin this identity's public key across restarts).
	signer, err := crypto.LoadOrCreateSigner(cfg.AgentKeyPath)
	if err != nil {
		log.Fatalf("[Crypto Error] Failed to initialize Ed25519 keypair: %v", err)
	}
	log.Printf("[Crypto] Ed25519 signer ready (key: %s). Agent Public Key: %s...",
		cfg.AgentKeyPath, signer.PublicKeyBase64()[:16])

	// 3. Initialize HTTP Egress Client & Heartbeat Watchdog
	egress.ConfigureFIM(cfg.FIMWebRoots, cfg.FIMDataDirs) // route FIM events iv/v by path
	egressClient, err := egress.NewClient(cfg, signer)
	if err != nil {
		log.Fatalf("[Egress Error] Failed to initialize Sentry transport: %v", err)
	}
	transportMode := "plaintext HTTP"
	if cfg.ClientCertPath != "" {
		transportMode = "mTLS (TLS 1.3, client cert)"
	}
	log.Printf("[Egress] Sentry transport: %s -> %s", transportMode, cfg.SentryBaseURL)
	heartbeatWatcher := egress.NewHeartbeatWatcher(cfg, egressClient)

	// Context for graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4. Start 5-second Heartbeat Watchdog in background goroutine
	go heartbeatWatcher.Start(ctx)

	// 4b. Start host-metrics reporter: the agent runs on the monitored host, so
	//     it samples the host's own vitals (CPU/mem/load/os) and ships them to
	//     Sentry's /host endpoint for the dashboard's System Health panel.
	go func() {
		hc := hostmetrics.New()
		ticker := time.NewTicker(hostmetrics.SampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := hc.Sample(cfg.AgentID, agentVersion, transportMode, 0)
				if err := egressClient.SendHost(ctx, snap); err != nil {
					log.Printf("[HostMetrics Warning] %v", err)
				}
			}
		}
	}()

	// 5. Start Log Collector Manager (restart-durable sequence numbers)
	collectorMgr, err := collector.NewManager(cfg)
	if err != nil {
		log.Fatalf("[Collector Error] Failed to open sequence store: %v", err)
	}
	collectorMgr.Start(ctx)

	// Listen for OS Interrupts (Ctrl+C / kill -9)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("[Daemon] Barbarika Go Daemon active and tailing logs...")

	// Main processing loop: consumes events from all active tailers
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-collectorMgr.EventChan:
				// Update Watchdog tracking pointers
				heartbeatWatcher.LastSeq = event.Sequence
				heartbeatWatcher.LastHash = event.Hash

				// Pretty log telemetry
				log.Printf("[EVENT #%d] Source: %-6s | SHA-256: %s | Payload: %s",
					event.Sequence, event.Source, event.Hash[:16]+"...", event.RawContent)

				// Ship the event to Sentry (POST /events). This is the joining
				// wire between the agent and Anuvrat's ingestion backend.
				if err := egressClient.SendEvent(ctx, event); err != nil {
					log.Printf("[Egress Error] %v", err)
				}
			}
		}
	}()

	// Wait for OS shutdown signal
	sig := <-sigChan
	log.Printf("[Daemon Shutdown] Received signal: %v. Cleaning up and exiting...", sig)
	cancel()
}
