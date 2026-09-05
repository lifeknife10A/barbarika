"""Thin CLI (for testing / batch generation; the primary UX is the dashboard button)."""

from __future__ import annotations

import argparse

from . import generate


def main() -> int:
    ap = argparse.ArgumentParser(description="Fill the official CERT-In Incident Reporting Form from the vault.")
    ap.add_argument("--db", required=True, help="Sentry vault sqlite path")
    ap.add_argument("--config", required=True, help="submission.toml")
    ap.add_argument("--incident", default="latest", help="incident_uuid or 'latest'")
    ap.add_argument("--out", required=True, help="output PDF path")
    ap.add_argument("--key", help="SENTRY_KEY_PATH (AES key file)")
    ap.add_argument("--rules-dir", help="rules/rules/v1")
    a = ap.parse_args()
    res = generate.generate_report(
        db_path=a.db, submission_path=a.config, out_pdf=a.out,
        incident=a.incident, key_path=a.key, rules_dir=a.rules_dir,
    )
    print(res["chain"].message)
    print("PDF:  ", res["pdf"])
    print("Email:", res["email"])
    print("Audit:", res["audit_ref"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
