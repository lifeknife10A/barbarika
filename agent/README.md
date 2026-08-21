# agent — Go ingestion daemon

Owner: Anay Modi (Systems Agent).

Runs on the **monitored primary server**. Target footprint: <25MB RSS.

## Scope

- Tail `journald` (JSON) / `/var/log/auth.log`, `/var/log/nginx/access.log`.
- `fsnotify` watcher on `/var/www` + a canary directory for file-integrity signal.
- Normalize + hash log lines in real time; in-memory batching with a bounded, crash-resilient
  local disk spool.
- Ed25519-sign each outbound batch.
- Zero network listeners — outbound-only. See `../transport/` for the mTLS/heartbeat pieces this
  daemon uses to talk to Sentry.

## Explicitly out of scope here

- Any classification/rule logic (that's `../rules/`).
- Remote configuration polling — excluded from the hackathon critical path per the audit.

## Quick Start & Verification

### Build & Run Tests
```bash
# Run unit tests
go test -v ./...

# Build daemon binary
go build -o bin/barbarika-agent ./cmd/agent
```

### Run Demo Mode
Streams realistic test telemetry (SSH brute-force + sudo + nginx exploit probe) through the `tail -> normalize -> Ed25519 sign` pipeline:
```bash
./bin/barbarika-agent -demo
```

### Tail Local Log File
```bash
./bin/barbarika-agent -file /var/log/auth.log -follow -source primary-srv-01
```
