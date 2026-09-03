# Barbarika Integration Contract — Agent ↔ Sentry

This is the **joining contract** between the Go agent (`agent/barbarika-agent/`,
Anay) and the Sentry ingestion backend (`SentryP/backend/`, Anuvrat). It is the
single source of truth for how the two components talk, so neither side has to
guess what the other sends or expects.

> Scope: this wires the two teammates' actual implementations together over
> plaintext HTTP first (the "they connect" milestone). mTLS is the next
> hardening step — see **Next hardening** below. Endpoints and payloads do not
> change when TLS is added; only the URL scheme and transport do.

## Topology

```
 agent/barbarika-agent (sender)                 SentryP/backend (receiver)
 ┌───────────────────────────┐   HTTP/JSON      ┌────────────────────────────┐
 │ tail logs → LogEvent       │  POST /events    │ /events   → hash chain → DB │
 │ SHA-256 + Ed25519 sign     │ ───────────────► │ /heartbeat→ store           │
 │ 5s heartbeat ticker        │  POST /heartbeat │ /health   → liveness        │
 └───────────────────────────┘                  │ GET /events → read back     │
                                                 └────────────────────────────┘
```

Canonical Sentry base URL: **`http://127.0.0.1:8000`** (agent env `SENTRY_URL`).

## Endpoints

| Method + path      | Sender → Receiver | Body model            | Success |
|--------------------|-------------------|-----------------------|---------|
| `POST /events`     | agent → sentry    | `EventIn`             | `201` + `EventOut` |
| `POST /heartbeat`  | agent → sentry    | `HeartbeatIn`         | `202` `{"detail":"heartbeat recorded"}` |
| `GET  /events`     | dashboard/tools   | —                     | `200` `[EventOut]` |
| `GET  /health`     | anyone            | —                     | `200` `{"status":"ok"}` |

## `POST /events` — `EventIn` (the important one)

```jsonc
{
  "agent_id":   "primary-srv-01",          // string, agent identity
  "sequence":   42,                         // int, monotonic per agent
  "timestamp":  "2026-09-04T12:00:01Z",     // ISO-8601 UTC
  "source":     "auth",                     // "auth" | "nginx" | ...
  "event_type": "ssh_failed_login",         // canonical type (table below)
  "payload": {                              // free JSON; agent proofs live here
    "raw_content":     "…Failed password for root from …",
    "agent_sha256":    "<hex sha-256 of the raw line>",
    "agent_pubkey":    "<base64 ed25519 public key>",
    "agent_signature": "<base64 ed25519 signature>"
  }
}
```

### Agent `LogEvent` → `EventIn` field mapping (implemented in `pkg/egress/mapping.go`)

| agent `LogEvent` | `EventIn`      | Notes |
|------------------|----------------|-------|
| `Sequence`       | `sequence`     | agent's atomic counter |
| `Timestamp`      | `timestamp`    | formatted RFC3339 UTC |
| `Source`         | `source`       | tailer source name |
| `RawContent`     | `payload.raw_content` | exact raw log line |
| `Hash`           | `payload.agent_sha256` | agent-side SHA-256 |
| —                | `event_type`   | derived by `classifyEventType` |
| —                | `agent_id`     | from agent config |
| —                | `payload.agent_signature` / `agent_pubkey` | Ed25519 over `agent_id|seq|ts|source|raw` |

### `classifyEventType` (joining-layer convenience)

| raw line contains…            | `event_type`       |
|-------------------------------|--------------------|
| `Failed password` / `authentication failure` | `ssh_failed_login` |
| `Accepted password` / `Accepted publickey`   | `ssh_login` |
| `sudo:`                        | `sudo_exec` |
| source `nginx` or `HTTP/`      | `http_request` |
| (anything else)                | `raw_log` |

## `POST /heartbeat` — `HeartbeatIn`

```jsonc
{
  "agent_id": "primary-srv-01", "boot_id": "…uuid…", "sequence": 7,
  "sent_at_utc": "2026-09-04T12:00:30Z",
  "last_event_sequence": 42, "last_event_hash": "<hex or empty>",
  "agent_health": "healthy", "signature": "<base64 ed25519>"
}
```
The agent sends one every 5s. `last_event_*` track the most recent ingested event.

## Hash chain (receiver side)

For each event Sentry computes, per `agent_id`, ordered by `sequence`:

```
cur_hash = SHA-256( prev_hash || canonical_ts || canonical_json(event_dict) )
```

where `canonical_ts` is UTC/tz-naive ISO (`hash_chain.to_utc_naive_iso`) and
`event_dict` excludes the hash fields. Verify with:

```
cd SentryP && python -m backend.scripts.verify_chain   # → [PASS] N records …
```

## Configuration knobs

| Side   | Knob            | Default                   |
|--------|-----------------|---------------------------|
| agent  | `SENTRY_URL`    | `http://localhost:8000`   |
| agent  | `AGENT_ID`      | `primary-srv-01`          |
| agent  | `BOOT_ID`       | fixed demo UUID           |
| sentry | uvicorn `--port`| `8000` (canonical)        |

## Run the end-to-end demo

```
integration/run_e2e.sh
```
Starts Sentry, runs the agent against a mock log, injects an SSH attack, shows
the events landing in Sentry, then verifies the chain (`[PASS]`) and demonstrates
tamper-evidence (`[FAIL]` after a row is mutated).

## Next hardening (not yet wired — tracked so it isn't forgotten)

1. **mTLS**: serve Sentry over TLS 1.3 with client-cert required (material exists
   in `transport/`), switch `SENTRY_URL` to `https://…`. No payload changes.
2. **Verify Ed25519 on receive**: the agent already ships `agent_pubkey` +
   `agent_signature` in `payload`; Sentry can verify before chaining.
3. **Single authoritative store**: Sentry currently *also* appends NDJSON
   evidence (`SentryP/backend/data/evidence/*.ndjson`) alongside SQLite — the
   architecture calls for one authoritative store. Drop the NDJSON dual-write.
4. **Sequence continuity**: the agent's `sequence` resets on restart; Sentry keys
   the chain on `(agent_id, sequence)`. Persist the counter or key the chain on
   `boot_id` to avoid post-restart collisions.
