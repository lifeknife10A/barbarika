package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"barbarika/agent/internal/daemon"
	"barbarika/agent/internal/normalizer"
	"barbarika/agent/internal/signer"
	"barbarika/agent/internal/spool"
)

func main() {
	sourceID := flag.String("source", "primary-srv-01", "Source identifier for this agent/host")
	authLog := flag.String("auth-log", "", "Path to auth.log to tail")
	nginxLog := flag.String("nginx-log", "", "Path to nginx access.log to tail")
	fileLog := flag.String("file", "", "Generic log file to tail (alias for auth-log)")
	watchDirs := flag.String("watch-dirs", "", "Comma-separated list of directories for fsnotify file integrity monitoring")
	canaryDir := flag.String("canary-dir", "", "Path to designated canary file/directory")
	spoolDir := flag.String("spool-dir", ".spool", "Local crash-resilient disk spool directory")
	maxSpoolMB := flag.Int64("max-spool-mb", 50, "Maximum bounded size for disk spool in MB")
	batchSize := flag.Int("batch-size", 25, "Maximum events per Ed25519-signed batch")
	flushPeriodMs := flag.Int("flush-ms", 500, "Flush period in milliseconds")
	follow := flag.Bool("follow", false, "Follow log files continuously (tail -f mode)")
	emitBatches := flag.Bool("batch", false, "Emit signed batch envelopes instead of single events")
	demoMode := flag.Bool("demo", false, "Run with simulated multi-source attack telemetry")
	flag.Parse()

	targetAuth := *authLog
	if targetAuth == "" && *fileLog != "" {
		targetAuth = *fileLog
	}
	targetNginx := *nginxLog

	var watchList []string
	if *watchDirs != "" {
		for _, d := range strings.Split(*watchDirs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				watchList = append(watchList, d)
			}
		}
	}

	targetCanary := *canaryDir
	targetSpool := *spoolDir

	if *demoMode {
		tmpDir, err := os.MkdirTemp("", "barbarika-demo-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating demo temp dir: %v\n", err)
			os.Exit(1)
		}
		defer os.RemoveAll(tmpDir)

		demoAuth := filepath.Join(tmpDir, "auth.log")
		demoNginx := filepath.Join(tmpDir, "access.log")
		demoWww := filepath.Join(tmpDir, "www")
		demoCanary := filepath.Join(tmpDir, "canary")
		targetSpool = filepath.Join(tmpDir, "spool")

		_ = os.MkdirAll(demoWww, 0755)
		_ = os.MkdirAll(demoCanary, 0755)

		sampleAuth := `Aug 22 01:15:01 web-primary sshd[31001]: Failed password for invalid user root from 203.0.113.42 port 51120 ssh2
Aug 22 01:15:02 web-primary sshd[31002]: Failed password for invalid user root from 203.0.113.42 port 51122 ssh2
Aug 22 01:15:03 web-primary sshd[31003]: Failed password for invalid user root from 203.0.113.42 port 51124 ssh2
Aug 22 01:15:05 web-primary sshd[31010]: Accepted publickey for attacker from 203.0.113.42 port 51130 ssh2
Aug 22 01:15:07 web-primary sudo:   attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
`
		sampleNginx := `203.0.113.42 - - [22/Aug/2026:01:15:09 +0000] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.6"
203.0.113.42 - - [22/Aug/2026:01:15:10 +0000] "POST /admin/upload.php HTTP/1.1" 200 45 "-" "curl/7.81.0"
`
		_ = os.WriteFile(demoAuth, []byte(sampleAuth), 0644)
		_ = os.WriteFile(demoNginx, []byte(sampleNginx), 0644)

		targetAuth = demoAuth
		targetNginx = demoNginx

		watchList = append(watchList, demoWww)
		targetCanary = demoCanary
	} else if targetAuth == "" && *nginxLog == "" && len(watchList) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Specify at least one log or directory source (-auth-log, -nginx-log, -watch-dirs) or run with -demo")
		flag.Usage()
		os.Exit(1)
	}

	if targetNginx == "" {
		targetNginx = *nginxLog
	}

	// Initialize cryptographic signer
	sig, err := signer.NewSigner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing Ed25519 signer: %v\n", err)
		os.Exit(1)
	}

	// Initialize normalizer
	norm := normalizer.NewNormalizer(*sourceID)

	// Initialize disk spool
	sp, err := spool.NewSpool(targetSpool, *maxSpoolMB*1024*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to open disk spool (%v), continuing in-memory\n", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	d := daemon.NewDaemon(daemon.Config{
		SourceID:     *sourceID,
		AuthLogPath:  targetAuth,
		NginxLogPath: targetNginx,
		WatchDirs:    watchList,
		CanaryDir:    targetCanary,
		SpoolDir:     targetSpool,
		MaxSpoolSize: *maxSpoolMB * 1024 * 1024,
		BatchSize:    *batchSize,
		FlushPeriod:  time.Duration(*flushPeriodMs) * time.Millisecond,
		Follow:       *follow,
		EmitBatches:  *emitBatches,
	}, sig, norm, sp, os.Stdout)

	if err := d.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Daemon stopped: %v\n", err)
	}
}
