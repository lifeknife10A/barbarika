package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"barbarika-agent/config"
	"barbarika-agent/pkg/collector"
	"barbarika-agent/pkg/crypto"
	"barbarika-agent/pkg/egress"
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("  BARBARIKA — Systems Ingestion Daemon & Evidence Engine (Go)  ")
	fmt.Println("=================================================================")

	// 1. Load configuration
	cfg := config.LoadConfig()
	log.Printf("[Config] Agent ID: %s | Sentry Endpoint: %s", cfg.AgentID, cfg.SentryBaseURL)

	// 2. Initialize Ed25519 Signer
	signer, err := crypto.NewSigner()
	if err != nil {
		log.Fatalf("[Crypto Error] Failed to initialize Ed25519 keypair: %v", err)
	}
	log.Printf("[Crypto] Ed25519 Signer initialized. Agent Public Key: %s...", signer.PublicKeyBase64()[:16])

	// 3. Initialize HTTP Egress Client & Heartbeat Watchdog
	egressClient := egress.NewClient(cfg, signer)
	heartbeatWatcher := egress.NewHeartbeatWatcher(cfg, egressClient)

	// Context for graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4. Start 5-second Heartbeat Watchdog in background goroutine
	go heartbeatWatcher.Start(ctx)

	// 5. Start Log Collector Manager
	collectorMgr := collector.NewManager(cfg)
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
			}
		}
	}()

	// Wait for OS shutdown signal
	sig := <-sigChan
	log.Printf("[Daemon Shutdown] Received signal: %v. Cleaning up and exiting...", sig)
	cancel()
}
