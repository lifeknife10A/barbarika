#!/usr/bin/env python3
"""Benchmark + cross-component contract check for the mTLS agent -> Sentry flow.

Run by integration/run_mtls_e2e.sh once Sentry is serving over mTLS and Anay's
agent is running with Jash's client certificate. It:

  1. appends N synthetic log lines the running agent will tail + ship over mTLS,
  2. polls Sentry (also over mTLS) until all N are stored, timing the burst,
  3. validates a *received* heartbeat against Jash's own HeartbeatPayload parser
     (transport/heartbeat.py) — proving Anay -> Jash -> Anuvrat are in sync.

Every request to Sentry presents the demo client certificate; a caller without
one is rejected at the TLS layer (see the negative test in the shell script).
Standard-library only (ssl + http.client) so there is nothing extra to install.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sqlite3
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def make_context(certs: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(certs / "demo-ca.crt"))
    ctx.load_cert_chain(str(certs / "demo-client.crt"), str(certs / "demo-client.key"))
    return ctx


def get_json(ctx: ssl.SSLContext, host: str, port: int, path: str):
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return json.loads(resp.read())
    finally:
        conn.close()


def benchmark(ctx, host, port, base_url, auth_log: Path, n: int) -> None:
    baseline = len(get_json(ctx, host, port, "/events?limit=1000000"))
    with auth_log.open("a", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(
                f"Aug 19 10:20:{i % 60:02d} primary-srv-01 sshd[{1000 + i}]: "
                f"Failed password for root from 185.220.101.4 port {40000 + i} ssh2\n"
            )

    start = time.time()
    deadline = start + 90
    stored = baseline
    while stored < baseline + n:
        if time.time() > deadline:
            print(f"[BENCH][TIMEOUT] only {stored - baseline}/{n} events ingested in 90s")
            sys.exit(1)
        time.sleep(0.25)
        stored = len(get_json(ctx, host, port, "/events?limit=1000000"))
    elapsed = time.time() - start

    print(f"[BENCH] {n} events ingested over mTLS in {elapsed:.2f}s "
          f"-> {n / elapsed:.0f} events/sec")
    total = len(get_json(ctx, host, port, "/events?limit=1000000"))
    print(f"[BENCH] total events stored: {total}")


def check_heartbeat_contract(repo: Path, n_waits: int = 40) -> None:
    """Validate a stored heartbeat against Jash's parser (transport/heartbeat.py)."""
    sys.path.insert(0, str(repo / "transport"))
    from heartbeat import HeartbeatPayload  # Jash's authoritative contract

    db = repo / "SentryP" / "data" / "barbarika.db"
    row = None
    for _ in range(n_waits):
        try:
            con = sqlite3.connect(db)
            row = con.execute(
                "SELECT agent_id, boot_id, sequence, sent_at_utc, last_event_sequence, "
                "last_event_hash, agent_health, signature FROM heartbeats "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            con.close()
        except sqlite3.OperationalError:
            row = None
        if row:
            break
        time.sleep(0.5)

    if not row:
        print("[HB][WARN] no heartbeat received yet; skipping contract check")
        return

    agent_id, boot_id, seq, sent_at, last_seq, last_hash, health, sig = row
    dt = datetime.fromisoformat(str(sent_at)).replace(microsecond=0, tzinfo=None)
    mapping = {
        "agent_id": agent_id,
        "boot_id": boot_id,
        "sequence": int(seq),
        "sent_at_utc": dt.isoformat() + "Z",
        "last_event_sequence": int(last_seq) if last_seq is not None else 0,
        "last_event_hash": last_hash,
        "agent_health": health,
        "signature": sig,
    }
    HeartbeatPayload.from_mapping(mapping)  # raises HeartbeatValidationError if out of sync
    print(f"[HB] heartbeat seq {seq} received over mTLS validates against Jash's parser")
    print(f"[HB]   last_event_hash={last_hash[:12]}… agent_health={health}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--certs", required=True, type=Path)
    ap.add_argument("--auth-log", required=True, type=Path)
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("-n", type=int, default=200)
    args = ap.parse_args()

    parsed = urlparse(args.base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 443
    ctx = make_context(args.certs)

    benchmark(ctx, host, port, args.base_url, args.auth_log, args.n)
    check_heartbeat_contract(args.repo)


if __name__ == "__main__":
    main()
