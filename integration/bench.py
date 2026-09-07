#!/usr/bin/env python3
"""Throughput benchmark for the agent -> Sentry (`sentry/`) ingest path.

Appends N synthetic log lines the running agent tails + ships, then polls the
Sentry SQLite store until all N are committed, reporting events/sec. Counting
via the DB keeps it independent of the `/events` API's page limit. Standard
library only.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path


def count(db: Path) -> int:
    try:
        con = sqlite3.connect(db)
        try:
            return con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            con.close()
    except sqlite3.OperationalError:
        return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auth-log", required=True, type=Path)
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("-n", type=int, default=200)
    args = ap.parse_args()

    baseline = count(args.db)
    with args.auth_log.open("a", encoding="utf-8") as fh:
        for i in range(args.n):
            fh.write(
                f"Aug 19 11:{(i // 60) % 60:02d}:{i % 60:02d} web sshd[{2000 + i}]: "
                f"Failed password for root from 198.51.100.9 port {40000 + i} ssh2\n"
            )

    start = time.time()
    deadline = start + 120
    stored = baseline
    while stored < baseline + args.n:
        if time.time() > deadline:
            print(f"[BENCH][TIMEOUT] only {stored - baseline}/{args.n} events in 120s")
            sys.exit(1)
        time.sleep(0.25)
        stored = count(args.db)
    elapsed = time.time() - start

    print(f"[BENCH] {args.n} events agent -> Sentry in {elapsed:.2f}s "
          f"-> {args.n / elapsed:.0f} events/sec")
    print(f"[BENCH] total events stored: {count(args.db)}")


if __name__ == "__main__":
    main()
