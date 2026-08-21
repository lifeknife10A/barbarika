# sentry — ingestion API + evidence vault

Owner: Anuvrat Tripathi (Storage & Backend).

Runs on the **isolated Sentry host** — trusted side of the trust boundary. If this host is ever
compromised, the evidence guarantees no longer hold; that's an acceptable, statable limit, not
something to paper over.

## Scope

- FastAPI + Pydantic V2 ingestion endpoint, strict rate limiting + payload bounding + certificate
  check (mTLS via `../transport/`).
- SQLite in WAL mode as the **single authoritative store** — avoid any NDJSON/SQLite dual-write
  inconsistency; pick one and make it authoritative.
- Append-only hash chain: `SHA-256(DomainSeparator || PrevHash || Sequence || ReceivedAt ||
  ExactEventBytes)`. This is tamper-*evidence*, not WORM — say that precisely if asked.
- AES-GCM encryption-at-rest for sensitive identifiers (IPs, account names); masked by default in
  any API response, unmask only via an authenticated, audited action.
- Hash-chain verification script: should run in well under a second for demo-scale record counts
  and print something like `[PASS] N records | valid signatures | contiguous sequence | chain
  intact`.
- Hosts the watchdog logic from `../transport/` on the receive side.

## Explicitly out of scope here

- Rule evaluation logic lives in `../rules/`; `sentry/` calls into it, doesn't own it.
- Report generation lives in `../compliance/`.

## Running

Managed with **uv**. From this folder:

```bash
uv sync --extra dev              # install deps (incl. ../rules as an editable dep)
uv run pytest                    # full suite (ingest, hash chain, detection, mTLS, SSE)
```

### Local dev (plaintext, mTLS bypassed)

```bash
SENTRY_DEV_INSECURE=1 uv run uvicorn app.main:app --reload   # http://127.0.0.1:8000
curl -s localhost:8000/health
curl -s -X POST localhost:8000/ingest -H 'content-type: application/json' \
  -d '{"event_type":"ssh_auth_failure","source":"primary-01/auth.log","category":"iii",
       "raw_message":"sshd[1]: Failed password for admin from 203.0.113.7 port 22 ssh2",
       "payload":{"src_ip":"203.0.113.7"}}'
```

`SENTRY_DEV_INSECURE=1` is a **local-only** switch that skips the client-cert check so
you can drive the API over plaintext HTTP. Never set it on a real host.

### With mTLS (demo PKI)

First generate the demo certs once (from `../transport`): `./scripts/generate_demo_certs.sh`.

```bash
CERTS=../transport/certs
SENTRY_CERT_DIR=$CERTS uv run uvicorn app.main:app --host 127.0.0.1 --port 8443 \
  --ssl-keyfile $CERTS/demo-server.key --ssl-certfile $CERTS/demo-server.crt \
  --ssl-ca-certs $CERTS/demo-ca.crt --ssl-cert-reqs 2      # 2 = CERT_REQUIRED

curl --cacert $CERTS/demo-ca.crt --resolve sentry.local:8443:127.0.0.1 \
     --cert $CERTS/demo-client.crt --key $CERTS/demo-client.key \
     https://sentry.local:8443/events
```

A client without a demo-CA-signed certificate never completes the TLS handshake.

## Endpoints

| Method + path        | Purpose |
|----------------------|---------|
| `POST /ingest`       | mTLS-gated. Seals content (AES-GCM), extends the hash chain, evaluates rules, records incidents, broadcasts live. Returns `{id, seq, received_at, row_hash}`. |
| `GET /events`        | Recent events, **masked by default**. |
| `GET /events/{id}`   | One event; `?unmask=true` needs header `X-Unmask-Token` = `SENTRY_UNMASK_TOKEN` (audited). |
| `GET /events/stream` | Server-Sent Events: replay recent, then live events + incidents (`?once=true` for a finite replay). |
| `GET /incidents`     | Incidents recorded when a detection rule fired. |
| `GET /health`        | status, `journal_mode`, counts, `rules_loaded`, mTLS mode. |

## What's implemented

- **Append-only hash chain** over the WAL store: `SHA-256(DomainSeparator || PrevHash ||
  Sequence || ReceivedAt || ExactEventBytes)`. Verify with:
  `uv run python scripts/verify_chain.py --db sentry.db` →
  `[PASS] N records | contiguous sequence | chain intact`. Tamper-*evidence* only
  (not WORM, no Ed25519 signature check — that's agent-side).
- **mTLS** (receive side): TLS 1.3, client cert required, demo CA the only trust anchor.
  Identity = verified CN forwarded via `X-Client-Cert-CN` from the TLS edge (uvicorn does
  not surface peer certs to ASGI); an authenticated https request with no header resolves
  to a generic verified identity.
- **Detection**: loads `../rules` YAML rules and evaluates each ingested event over an
  in-memory correlation window; Category (iii) SSH brute-force fires an incident today.
- **AES-GCM at rest** for the sensitive part (raw_message + payload); identifiers (IPs,
  accounts) **masked by default** in every response.

Config: `SENTRY_DB_PATH`, `SENTRY_KEY_PATH`/`SENTRY_MASTER_KEY`, `SENTRY_CERT_DIR`,
`BARBARIKA_RULES_DIR`, `SENTRY_UNMASK_TOKEN`, `SENTRY_CLIENT_CN_HEADER`. The `.db*`/`.key`
files are git-ignored.

**Still out (deliberately):** rate limiting + payload bounding beyond field limits, the
receive-side watchdog wiring, Ed25519 signature verification, real multi-worker chain
serialization (the append lock assumes a single process for the demo).
