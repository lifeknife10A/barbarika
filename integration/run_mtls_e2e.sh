#!/usr/bin/env bash
#
# Barbarika end-to-end over mTLS against the canonical `sentry/`:
#   Anay (agent) --mTLS/TLS1.3--> Jash (certs) --> Anuvrat (sentry/ vault + detection)
#
#   1. generate the demo PKI (Jash's transport/cert_generator.py)
#   2. start `sentry/` over TLS 1.3 with client-cert REQUIRED
#   3. prove a cert-less client is rejected
#   4. run the agent with the client cert; inject a Category (iii) attack
#   5. show masked + AES-GCM-sealed events, a fired incident (live detection),
#      a passing hash chain, and ingest throughput.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SENTRY_DIR="${REPO}/sentry"
AGENT_DIR="${REPO}/agent/barbarika-agent"
PORT="${SENTRY_PORT:-8443}"
BASE_URL="https://127.0.0.1:${PORT}"
BENCH_N="${BENCH_N:-200}"

WORK="$(mktemp -d)"
CERTS="${WORK}/certs"
mkdir -p "${WORK}/mock_logs"
AGENT_BIN="${WORK}/barbarika-agent"
DB="${WORK}/sentry.db"
KEY="${WORK}/sentry.key"

SENTRY_PID=""
AGENT_PID=""
cleanup() {
  for pid in "${AGENT_PID}" "${SENTRY_PID}"; do [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true; done
  sleep 0.5
  for pid in "${AGENT_PID}" "${SENTRY_PID}"; do [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true; done
  rm -rf "${WORK}"
}
trap cleanup EXIT
banner() { printf '\n=== %s ===\n' "$1"; }
mtls() { curl -sS --noproxy '*' --cacert "${CERTS}/demo-ca.crt" \
  --cert "${CERTS}/demo-client.crt" --key "${CERTS}/demo-client.key" "$@"; }

banner "Syncing sentry/ deps"
( cd "${SENTRY_DIR}" && uv sync --extra dev >/dev/null 2>&1 )

banner "Generating demo PKI (Jash: transport/cert_generator.py)"
( cd "${SENTRY_DIR}" && uv run python "${REPO}/transport/cert_generator.py" --output-dir "${CERTS}" --force )

banner "Building agent"
( cd "${AGENT_DIR}" && go build -o "${AGENT_BIN}" . )

banner "Starting sentry/ over mTLS on ${BASE_URL} (client cert REQUIRED)"
if curl -sS --noproxy '*' -k "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "ERROR: ${BASE_URL} already serving — free port ${PORT} (SENTRY_PORT) and retry." >&2
  exit 1
fi
( cd "${SENTRY_DIR}" && SENTRY_CERT_DIR="${CERTS}" SENTRY_DB_PATH="${DB}" SENTRY_KEY_PATH="${KEY}" \
    exec uv run uvicorn app.main:app --host 127.0.0.1 --port "${PORT}" \
      --ssl-keyfile "${CERTS}/demo-server.key" --ssl-certfile "${CERTS}/demo-server.crt" \
      --ssl-ca-certs "${CERTS}/demo-ca.crt" --ssl-cert-reqs 2 >"${WORK}/sentry.log" 2>&1 ) &
SENTRY_PID=$!
for _ in $(seq 1 40); do mtls "${BASE_URL}/health" >/dev/null 2>&1 && break; sleep 0.5; done
printf '  health (with client cert): '; mtls "${BASE_URL}/health"; echo

banner "Negative test: connect WITHOUT a client cert (must fail)"
if curl -sS --noproxy '*' --cacert "${CERTS}/demo-ca.crt" "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "  UNEXPECTED: cert-less client accepted — mTLS not enforced!" >&2; exit 1
else
  echo "  OK: TLS layer rejected the cert-less client (mutual auth enforced)"
fi

banner "Starting agent over mTLS (presents Jash's demo-client cert)"
printf 'Aug 19 10:14:00 web sshd[100]: Server listening on port 22\n' > "${WORK}/mock_logs/auth.log"
: > "${WORK}/mock_logs/nginx_access.log"
( cd "${WORK}" && SENTRY_URL="${BASE_URL}" AGENT_ID="primary-srv-01" \
    SENTRY_CA_CERT="${CERTS}/demo-ca.crt" SENTRY_CLIENT_CERT="${CERTS}/demo-client.crt" \
    SENTRY_CLIENT_KEY="${CERTS}/demo-client.key" exec "${AGENT_BIN}" >"${WORK}/agent.log" 2>&1 ) &
AGENT_PID=$!
sleep 2

banner "Injecting Category (iii): 12 failed SSH + 1 accepted"
AUTH="${WORK}/mock_logs/auth.log"
for i in $(seq 1 12); do
  printf 'Aug 19 10:15:%02d web sshd[90%02d]: Failed password for root from 203.0.113.7 port 41%03d ssh2\n' "$i" "$i" "$i" >> "${AUTH}"
done
printf 'Aug 19 10:16:00 web sshd[9099]: Accepted password for ubuntu from 203.0.113.7 port 42001 ssh2\n' >> "${AUTH}"
sleep 4

banner "Events masked + sealed"
mtls "${BASE_URL}/events?limit=3" | python3 -c "import sys,json;d=json.load(sys.stdin);print(f'  masked={d[0][\"masked\"]}; e.g. {d[0][\"event_type\"]} cat={d[0][\"category\"]} | {d[0][\"raw_message\"][:60]}')"
if grep -q "203.0.113.7" "${DB}" 2>/dev/null; then echo "  LEAK: cleartext IP in DB!"; exit 1; else echo "  sealed: no cleartext IP in the DB file (AES-GCM)"; fi

banner "Detection (GET /incidents over mTLS)"
mtls "${BASE_URL}/incidents" | python3 -c "import sys,json;d=json.load(sys.stdin);assert d,'no incident fired';print(f'  {len(d)} incident(s): {d[0][\"category\"]} — {d[0][\"rule_title\"]} ({len(d[0][\"event_ids\"])} events)')"

banner "Benchmark: ${BENCH_N} events agent -> mTLS -> sentry/"
python3 "${SCRIPT_DIR}/bench.py" --auth-log "${AUTH}" --db "${DB}" -n "${BENCH_N}"

banner "Provenance: agent signatures verify + rogue key rejected"
( cd "${SENTRY_DIR}" && uv run python "${SCRIPT_DIR}/check_provenance.py" --base-url "${BASE_URL}" --certs "${CERTS}" )

banner "Verify hash chain"
( cd "${SENTRY_DIR}" && SENTRY_DB_PATH="${DB}" SENTRY_KEY_PATH="${KEY}" uv run python scripts/verify_chain.py --db "${DB}" )

banner "mTLS END-TO-END OK"
grep -m1 "Egress. Sentry transport" "${WORK}/agent.log" | sed 's/^/  /' || true
