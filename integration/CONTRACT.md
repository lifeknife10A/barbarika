# Barbarika Integration Contract — Agent ↔ Sentry

This is the **joining contract** between the Go agent (`agent/barbarika-agent/`,
Anay) and the Sentry ingestion backend (`SentryP/backend/`, Anuvrat). It is the
single source of truth for how the two components talk, so neither side has to
guess what the other sends or expects.

> Two transports, same endpoints and payloads:
> - **Plaintext** (`http://…`) — simplest, `integration/run_e2e.sh`.
> - **mTLS / TLS 1.3** (`https://…`) — Anay's agent presents Jash's client
>   certificate; Anuvrat's Sentry requires it. `integration/run_mtls_e2e.sh`.
>   This is the intended trust boundary: **Anay (agent) → Jash (mTLS) → Anuvrat
>   (Sentry)**. See **mTLS transport** below.

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

| Side   | Knob                       | Default                   |
|--------|----------------------------|---------------------------|
| agent  | `SENTRY_URL`               | `http://localhost:8000`   |
| agent  | `AGENT_ID`                 | `primary-srv-01`          |
| agent  | `BOOT_ID`                  | fixed demo UUID           |
| agent  | `AGENT_KEY_PATH`           | `./agent_ed25519.key` (stable signing key) |
| agent  | `SENTRY_CA_CERT`           | — (verify Sentry over TLS)   |
| agent  | `SENTRY_CLIENT_CERT`       | — (agent client identity)    |
| agent  | `SENTRY_CLIENT_KEY`        | — (agent client key)         |
| sentry | uvicorn `--port`           | `8000` (canonical)        |
| sentry | `SENTRY_CLIENT_CN_HEADER`  | `x-client-cert-cn` (authoritative identity) |
| sentry | `SENTRY_REQUIRE_SIGNATURE` | off (`1` rejects unsigned events) |
| sentry | `SENTRY_DB_PATH`           | `SentryP/data/barbarika.db` |

## Key-to-identity binding

Signature verification proves the *presented* key signed the event; binding
proves it is the *expected* key for that identity:

- **Identity** = the verified mTLS client-cert CN when a TLS edge forwards it
  (`X-Client-Cert-CN`, authoritative), otherwise the event's `agent_id` (demo
  fallback; still gated by the mTLS transport). Set via `SENTRY_CLIENT_CN_HEADER`.
- **Pinning (TOFU)** — the first verified key seen for an identity is pinned in
  the `agent_keys` table. A later event for that identity presenting a *different*
  key is rejected with **HTTP 409** (impersonation / key swap), even though its
  own signature is valid.
- The agent persists its Ed25519 key at `AGENT_KEY_PATH`, so the pin survives
  restarts. Each event carries `signer_identity` in `EventOut`.

When `SENTRY_URL` is `https://…`, the agent builds a TLS 1.3 mutual-auth client
from the three cert vars; otherwise it stays plaintext.

## mTLS transport (Jash)

The demo PKI comes from Jash's `transport/cert_generator.py` (or
`generate_demo_certs.sh`): a demo CA, a server cert (`CN=sentry.local`, SAN
includes `127.0.0.1`), and a client cert (`CN=primary-srv-01`).

- **Sentry (server)** — start uvicorn with TLS + client cert required:
  ```
  uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 \
    --ssl-keyfile  certs/demo-server.key --ssl-certfile certs/demo-server.crt \
    --ssl-ca-certs certs/demo-ca.crt     --ssl-cert-reqs 2      # 2 = CERT_REQUIRED
  ```
  A client with no demo-CA-signed certificate never completes the handshake.
- **Agent (client)** — set `SENTRY_URL=https://127.0.0.1:8000` plus the three
  cert vars. Connecting to `127.0.0.1` matches the server cert SAN, so no
  `/etc/hosts` edit is needed (use `sentry.local` if you prefer).

Enforcement is at the TLS layer (transport-guaranteed authentication). Binding
the verified client-cert CN to an application identity is the same follow-up the
main `sentry/` documents; the agent already ships `agent_pubkey` +
`agent_signature` in each event payload so receive-side Ed25519 verification can
be added without a wire change.

## Benchmark

`integration/run_mtls_e2e.sh` runs the full flow and calls `integration/bench.py`
to append N events, poll Sentry (over mTLS) until all N are stored, and report
throughput — then validates a *received* heartbeat against Jash's own parser.
Reference numbers on a laptop-class machine: **~200 events in <2s (~100/sec)**,
chain `[PASS]`. Tune the load with `BENCH_N=500 integration/run_mtls_e2e.sh`.

> Windows/macOS: the scripts are bash (Linux/macOS). On Windows, run the same
> steps in PowerShell — generate certs with `python transport\cert_generator.py`,
> start Sentry with the uvicorn command above, and launch the agent with the
> `SENTRY_URL`/cert env vars set. `bench.py` is standard-library Python and runs
> anywhere.

## Run the end-to-end demo

```
integration/run_e2e.sh
```
Starts Sentry, runs the agent against a mock log, injects an SSH attack, shows
the events landing in Sentry, then verifies the chain (`[PASS]`) and demonstrates
tamper-evidence (`[FAIL]` after a row is mutated).

## Done in this integration

- **mTLS / TLS 1.3** wired end-to-end (agent client cert ⇄ Sentry, Jash's PKI).
- **Receive-side Ed25519 verification**: Sentry verifies each event's signature
  over the exact signed bytes (`services/signatures.py`), stores the result
  (`signature_verified`, `signer_pubkey`, exposed in `EventOut`), and **rejects a
  present-but-invalid signature with HTTP 400** (tampering). Unsigned events are
  accepted unless `SENTRY_REQUIRE_SIGNATURE=1`. The mTLS benchmark proves the
  real Go-agent signatures verify (201/201).
- **Key-to-identity binding**: the agent's Ed25519 key is persisted
  (`AGENT_KEY_PATH`) and pinned to its identity on first verified use; a rogue
  key claiming a pinned identity is rejected with HTTP 409. Proven end-to-end
  (all events pinned to `primary-srv-01`; impersonation → 409).
- **Heartbeat contract sync**: the agent's heartbeat conforms to Jash's
  `heartbeat.schema.json` (Go test `TestHeartbeatConformsToJashSchema`) and a
  *received* heartbeat validates against Jash's Python parser in the benchmark.
- **Sentry robustness**: SQLite `busy_timeout` + `synchronous=NORMAL` so the
  dashboard/benchmark can read `/events` while the agent writes (was
  "database is locked"); verifier timestamp bug fixed (chain verifies clean);
  `SENTRY_DB_PATH` override for isolated tests.

## Next hardening (tracked so it isn't forgotten)

1. **Forward the mTLS CN**: pinning uses `agent_id` in the direct demo because
   uvicorn does not surface the peer cert to the app. Put a TLS-terminating edge
   (or a small ASGI shim) in front that sets `X-Client-Cert-CN` from the verified
   client cert, so identity is the certificate CN, not a JSON field. Also allow
   pre-registering known keys instead of trust-on-first-use.
2. **Single authoritative store**: Sentry currently *also* appends NDJSON
   evidence (`SentryP/backend/data/evidence/*.ndjson`) alongside SQLite — the
   architecture calls for one authoritative store. Drop the NDJSON dual-write.
3. **`GET /events` default `limit=100`**: fine for the dashboard's recent view,
   but paginate (or raise the limit) for full history; `bench.py` passes an
   explicit large `limit`.
4. **Agent egress durability**: on a failed POST the agent logs and drops the
   event (no retry/spool, unlike the original `agent/` tree). Add a bounded
   retry/spool so a transient Sentry blip doesn't lose evidence.
5. **Sequence continuity**: the agent's `sequence` resets on restart; Sentry keys
   the chain on `(agent_id, sequence)`. Persist the counter or key the chain on
   `boot_id` to avoid post-restart collisions.
6. **Heartbeat pointer race**: the agent updates `LastSeq`/`LastHash` from the
   event goroutine while the heartbeat goroutine reads them (benign data race);
   guard with an atomic/mutex.
