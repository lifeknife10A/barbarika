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

## Log sources & the "empty feed" gotcha

The agent collects from these sources in parallel (each fails soft — a missing one
logs a clear `[Tailer Error] Failed to open …` / `[Journald] journalctl not found …`
warning and the others keep running). On start it prints `[Collector] active sources: …`.

| Source | Path / command | Notes |
|--------|----------------|-------|
| `journald` | `journalctl -f -n 30 -o short-iso` | **On by default.** Keeps the feed alive on systemd-only hosts. Disable with `BARBARIKA_JOURNALD=0`. |
| `auth` | `/var/log/auth.log` | SSH / sudo / login. **May not exist on Ubuntu 24.04** (see below). |
| `nginx` | `/var/log/nginx/access.log` | Web requests. Only present if nginx is installed. |
| `fim` | `FIM_WEB_ROOTS` / `FIM_DATA_DIRS` | File-integrity (Cat iv/v). Empty roots ⇒ FIM off. |

**If the feed is empty with no attack running**, it's almost always one of:
- **`/var/log/auth.log` doesn't exist.** Ubuntu 24.04 minimal/desktop images often ship
  without `rsyslog`, so auth goes to journald only. The `journald` source covers this;
  if you also want the classic file, `sudo apt install rsyslog`.
- **No nginx** ⇒ no `/var/log/nginx/access.log` ⇒ no web-traffic source.
- **Permissions.** `auth.log` is `640 root:adm` and the journal needs group access — run the
  agent as **root**, or a user in the **`adm`** and **`systemd-journal`** groups, or the reads
  fail and the source stays silent.
- **A genuinely quiet host** simply has little to report until there's activity.

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
