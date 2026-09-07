#!/usr/bin/env bash
#
# Barbarika end-to-end (plaintext, dev mode) against the canonical `sentry/`.
#
#   1. start `sentry/` (SENTRY_DEV_INSECURE=1 — skips the client-cert check)
#   2. run the Go agent against it (POST /ingest)
#   3. inject a Category (iii) SSH brute-force -> success attack
#   4. show events (masked + AES-GCM sealed), a fired incident (live detection),
#      and a passing hash chain.
#
# For the real mTLS path + benchmark, use integration/run_mtls_e2e.sh.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SENTRY_DIR="${REPO}/sentry"
AGENT_DIR="${REPO}/agent/barbarika-agent"
PORT="${SENTRY_PORT:-8000}"
BASE_URL="http://127.0.0.1:${PORT}"

WORK="$(mktemp -d)"
mkdir -p "${WORK}/mock_logs"
AGENT_BIN="${WORK}/barbarika-agent"
DB="${WORK}/sentry.db"
KEY="${WORK}/sentry.key"

SENTRY_PID=""
AGENT_PID=""
cleanup() {
  for pid in "${AGENT_PID}" "${SENTRY_PID}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
  done
  sleep 0.5
  for pid in "${AGENT_PID}" "${SENTRY_PID}"; do
    [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true
  done
  rm -rf "${WORK}"
}
trap cleanup EXIT
banner() { printf '\n=== %s ===\n' "$1"; }
q() { curl -fsS --noproxy '*' "$@"; }

banner "Syncing sentry/ deps"
( cd "${SENTRY_DIR}" && uv sync --extra dev >/dev/null 2>&1 )

banner "Building agent"
( cd "${AGENT_DIR}" && go build -o "${AGENT_BIN}" . )

banner "Starting sentry/ (dev-insecure) on ${BASE_URL}"
if q "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "ERROR: ${BASE_URL} already serving — free port ${PORT} (SENTRY_PORT) and retry." >&2
  exit 1
fi
( cd "${SENTRY_DIR}" && SENTRY_DEV_INSECURE=1 SENTRY_DB_PATH="${DB}" SENTRY_KEY_PATH="${KEY}" \
    exec uv run uvicorn app.main:app --host 127.0.0.1 --port "${PORT}" >"${WORK}/sentry.log" 2>&1 ) &
SENTRY_PID=$!
for _ in $(seq 1 40); do q "${BASE_URL}/health" >/dev/null 2>&1 && break; sleep 0.5; done
printf '  health: '; q "${BASE_URL}/health"; echo

banner "Starting agent (SENTRY_URL=${BASE_URL})"
printf 'Aug 19 10:14:00 web sshd[100]: Server listening on port 22\n' > "${WORK}/mock_logs/auth.log"
: > "${WORK}/mock_logs/nginx_access.log"
( cd "${WORK}" && SENTRY_URL="${BASE_URL}" AGENT_ID="primary-srv-01" \
    exec "${AGENT_BIN}" >"${WORK}/agent.log" 2>&1 ) &
AGENT_PID=$!
sleep 2

banner "Injecting Category (iii): 12 failed SSH + 1 accepted (same host, <60s)"
AUTH="${WORK}/mock_logs/auth.log"
for i in $(seq 1 12); do
  printf 'Aug 19 10:15:%02d web sshd[90%02d]: Failed password for root from 203.0.113.7 port 41%03d ssh2\n' "$i" "$i" "$i" >> "${AUTH}"
done
printf 'Aug 19 10:16:00 web sshd[9099]: Accepted password for ubuntu from 203.0.113.7 port 42001 ssh2\n' >> "${AUTH}"
sleep 4

banner "Events (masked + sealed)"
q "${BASE_URL}/events?limit=3" | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'  {len(d)} shown; masked={d[0][\"masked\"]}; e.g. {d[0][\"event_type\"]} cat={d[0][\"category\"]} | {d[0][\"raw_message\"][:64]}')"
if grep -q "203.0.113.7" "${DB}" 2>/dev/null; then echo "  LEAK: cleartext IP in DB!"; exit 1; else echo "  sealed: no cleartext IP in the DB file (AES-GCM)"; fi

banner "Detection (GET /incidents)"
q "${BASE_URL}/incidents" | python3 -c "import sys,json;d=json.load(sys.stdin);assert d,'no incident fired';print(f'  {len(d)} incident(s): {d[0][\"category\"]} — {d[0][\"rule_title\"]} ({len(d[0][\"event_ids\"])} events)')"

banner "Verify hash chain"
( cd "${SENTRY_DIR}" && SENTRY_DB_PATH="${DB}" SENTRY_KEY_PATH="${KEY}" uv run python scripts/verify_chain.py --db "${DB}" )

banner "END-TO-END OK"
