# transport — mTLS + heartbeat + watchdog

Owner: Jash Saraf (Transport & Security). Two constraints apply throughout this folder: heartbeat
loss is never automatically Category (ii), and "zero inbound" means no listener / no inbound
firewall rule required — not a claim of being unhackable or air-gapped.

Cross-cutting: consumed by both `../agent/` (sender) and `../sentry/` (receiver/watchdog), so it
lives in its own folder rather than duplicated in either.

## Scope

- Outbound HTTPS with TLS 1.3 **mutual** authentication (mTLS) — agent identity comes from the
  verified client certificate, not a JSON `agent_id` field.
- 5-second signed heartbeat payload shape (see the blueprint doc for the exact JSON schema).
- Watchdog state machine: `HEALTHY` → 3 missed heartbeats (15s) → `TELEMETRY_LOSS`. From there,
  branch on whether high-confidence intrusion evidence exists in the preceding 120s window — if
  not, it's an operational warning; if so, it's a **candidate** Category (ii) requiring human
  confirmation. Never auto-confirm.
- Cert issuance/rotation for the local demo (self-signed CA is fine for the hackathon; label it
  as such, don't imply production PKI).

## Note on the 15-second watchdog threshold

That's a demo threshold, tuned for a 3-minute stage script. Label it as such wherever it's
surfaced — it is not a claim about production-grade compromise detection latency.

## Local demo setup

Generate short-lived, self-signed demo identities:

```sh
./scripts/generate_demo_certs.sh          # needs openssl + bash
# or, no openssl/bash required (e.g. on Windows):
python cert_generator.py                  # add --force to rotate an existing set
```

Both tools are interchangeable: `cert_generator.py` reproduces the same OpenSSL profiles in
`certs/*.cnf` (CA `CN=Barbarika Demo-Only Local CA`, server `CN=sentry.local` with
`SAN=sentry.local,localhost,127.0.0.1` and `serverAuth`, client `CN=primary-srv-01` with
`clientAuth`), so the demo mTLS command in `../sentry/README.md` works against either set.

These certificates are **demo-only, not production PKI**. Each tool creates a local CA plus one
server and one client identity under `certs/`; their private material is git-ignored, and both
refuse to overwrite an existing set without an explicit force flag. See
[`certs/README.md`](certs/README.md) for the trust and rotation boundaries. TLS 1.3 enforcement and
network connections are intentionally not implemented here yet.

The language-neutral payload contract is [`heartbeat.schema.json`](heartbeat.schema.json).
[`heartbeat.py`](heartbeat.py) provides strict payload parsing, canonical signing bytes, a
signer-callback payload generator, and a deterministic watchdog state machine. The generator owns
only sequence advancement; Ed25519 key storage/signing stays with its caller. The watchdog uses
caller-supplied monotonic timestamps. There is no network code.

Run the standalone standard-library test suite:

```sh
python3 -m unittest discover -s tests -v
```

With the demo defaults, the watchdog moves from `HEALTHY` to `TELEMETRY_LOSS` after three missed
5-second intervals. `TELEMETRY_LOSS` alone remains an operational warning. High-confidence
intrusion evidence within the preceding 120 seconds produces only a candidate Category (ii)
disposition requiring human confirmation; the module never confirms or reports an incident.
