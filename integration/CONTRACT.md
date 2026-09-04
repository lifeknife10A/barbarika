# Barbarika Integration Contract — Agent ↔ Sentry (`sentry/`)

The **joining contract** between the Go agent (`agent/barbarika-agent/`, Anay) and
the canonical Sentry vault (`sentry/`, Anuvrat's domain), over Jash's mTLS
(`transport/`). The team chose **Option A**: the integration targets the canonical
`sentry/` backend (AES-GCM at rest, masking, hash chain with a receipt time + an
append lock, SSE, and the detection engine already wired to `barbarika_rules`).

> `SentryP/` (Anuvrat's earlier hand-built backend) is no longer the integration
> target. It stays in the repo; the pipeline points at `sentry/`.

## Topology

```
 agent/barbarika-agent (sender)                 sentry/ (vault + detection)
 ┌───────────────────────────┐   HTTP/JSON      ┌────────────────────────────────┐
 │ tail logs → LogEvent       │  POST /ingest    │ seal (AES-GCM) → hash chain → DB │
 │ SHA-256 + Ed25519 sign     │ ───────────────► │ evaluate rules → incidents       │
 │ persistent seq + boot_id   │  (mTLS 1.3)      │ mask reads · SSE · verify_chain  │
 └───────────────────────────┘                  └────────────────────────────────┘
```

Base URL: mTLS `https://127.0.0.1:8443` (demo) or dev-plaintext `http://…:8000`
(`SENTRY_DEV_INSECURE=1`). The server cert SAN includes `127.0.0.1`, so no hosts entry.

## Endpoints (`sentry/app/main.py`)

| Method + path        | Purpose |
|----------------------|---------|
| `POST /ingest`       | Seal + chain the event, run detection, broadcast. Returns `{id, seq, received_at, row_hash}`. Sentry assigns `seq` + `received_at`. |
| `GET  /events`       | Recent events, **masked by default** (`limit` 1–500). |
| `GET  /events/{id}`  | One event; `?unmask=true` needs header `X-Unmask-Token` = `SENTRY_UNMASK_TOKEN` (audited). |
| `GET  /events/stream`| SSE: replay recent, then live `event`/`incident` messages (for the dashboard). |
| `GET  /incidents`    | Incidents recorded when a detection rule fired. |
| `GET  /health`       | status, journal_mode, counts, `rules_loaded`, mTLS mode. |

## `POST /ingest` — `EventIn`

`EventIn` **forbids extra top-level fields**, so agent provenance rides in `payload`.

```jsonc
{
  "event_type": "ssh_failed_login",         // classifyEventType()
  "source":     "primary-srv-01/auth",       // "<agent_id>/<log>"
  "severity":   "warn",
  "category":   "iii",                       // candidate CERT-In id (omitted if none)
  "occurred_at":"2026-09-04T06:37:00.12345Z", // ISO-8601 UTC (the signed timestamp)
  "detected_at":"2026-09-04T06:37:00.12345Z",
  "raw_message":"…Failed password for root from 203.0.113.7 …",
  "payload": {
    "agent_id":        "primary-srv-01",
    "agent_sequence":  42,                    // agent's restart-durable seq
    "agent_sha256":    "<hex sha-256 of the raw line>",
    "agent_pubkey":    "<base64 ed25519 public key>",
    "agent_signature": "<base64 ed25519 signature>"
  }
}
```

### Mapping (`agent/barbarika-agent/pkg/egress/mapping.go`)

| agent `LogEvent` | `EventIn` | Notes |
|------------------|-----------|-------|
| `RawContent`     | `raw_message` | exact log line |
| —                | `event_type`  | `classifyEventType` |
| `Source`         | `source`      | prefixed with `<agent_id>/` |
| —                | `severity`    | `severityFor(event_type)` |
| —                | `category`    | `candidateCategory(event_type)` — which rules evaluate it |
| `Timestamp`      | `occurred_at`/`detected_at` | RFC3339 UTC |
| `Sequence`/`Hash`| `payload.agent_sequence`/`agent_sha256` | provenance |
| —                | `payload.agent_pubkey`/`agent_signature` | Ed25519 over `event_type\|source\|occurred_at\|raw_message` |

### `candidateCategory` → detection

The agent tags each event with the CERT-In category whose rules should evaluate it
(detection confirms an incident within that category). Today: SSH/sudo → `iii`
(fires the existing rule). **Extend this map with Anishka as her iv/x/v rules land**
— it is the bridge between telemetry and rules. Events with no category are still
stored + chained, just not rule-evaluated.

## Configuration

| Side   | Knob | Default / note |
|--------|------|----------------|
| agent  | `SENTRY_URL` | `http://localhost:8000` (`https://…` enables mTLS) |
| agent  | `AGENT_ID` / `BOOT_ID` | `primary-srv-01` / fresh v4 UUID per boot |
| agent  | `AGENT_KEY_PATH` / `AGENT_SEQ_PATH` | `./agent_ed25519.key` / `./agent_seq.state` |
| agent  | `SENTRY_CA_CERT` / `SENTRY_CLIENT_CERT` / `SENTRY_CLIENT_KEY` | mTLS client identity |
| sentry | `SENTRY_DEV_INSECURE=1` | dev only — skips the client-cert check |
| sentry | `SENTRY_CERT_DIR` / `SENTRY_DB_PATH` / `SENTRY_KEY_PATH` | mTLS certs / DB / AES key |
| sentry | `SENTRY_UNMASK_TOKEN` / `BARBARIKA_RULES_DIR` | unmask audit token / rules dir |

## Run

```
integration/run_e2e.sh        # plaintext dev: ingest, seal, mask, detection, chain
integration/run_mtls_e2e.sh   # mTLS + cert-less-rejected + detection + benchmark
```

## Done

- **Pipeline switched to `sentry/`** (Option A): agent → `POST /ingest` end-to-end.
- **Vault features (from `sentry/`)**: AES-GCM sealing at rest (no cleartext in the
  DB), masking by default, hash chain with `received_at` + a process-wide append
  lock, contiguous-sequence verification (`scripts/verify_chain.py`).
- **Live detection**: category-tagged events are rule-evaluated; the Category (iii)
  SSH brute-force rule fires an incident end-to-end (proven: 1 incident, 13 events).
- **mTLS 1.3** with Jash's PKI; cert-less client rejected.
- **Receive-side Ed25519 verification + key pinning (ported into `sentry/`)**:
  `POST /ingest` verifies the signature over the raw body, rejects a present-but-
  invalid signature (400), pins the verified key to the mTLS identity and rejects
  a rogue key (409); `signature_verified`/`signer_identity` exposed in `EventOut`.
  Proven end-to-end: 214/214 agent signatures verified, rogue → 409.
- **Agent robustness**: restart-durable sequence + per-boot `boot_id`.

## Next

1. **Rules (Anishka)**: extend `candidateCategory` + add the iv/x/v rules; they plug
   into `sentry/`'s already-wired detector.
2. **Dashboard (Nandini)**: connect to `GET /events/stream` (SSE) — reconcile the
   UI's `telemetry`/`heartbeat` event names with Sentry's `event`/`incident`; it can
   now surface the real `signature_verified`/`signer_identity` in provenance.
3. **Forward the mTLS CN for per-agent pinning**: in the direct demo the pinned
   identity is the generic `mtls-client` (uvicorn doesn't surface the peer cert).
   A TLS edge that sets `X-Client-Cert-CN` makes the identity the real certificate
   CN, so pinning is per-agent. Optionally require signatures (`SENTRY_REQUIRE_SIGNATURE=1`).
4. **Heartbeat receive-side**: `sentry/` has no `/heartbeat` (watchdog is a
   documented gap); the agent still emits heartbeats for the future watchdog.
5. Minor: `sentry/`'s `mask_text` over-masks `HH:MM:SS` as `«ip»` (safe over-mask).
