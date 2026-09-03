#!/usr/bin/env bash
#
# Barbarika end-to-end over mTLS — all three components in sync:
#   Anay (agent)  --mTLS/TLS1.3-->  Jash (certs)  -->  Anuvrat (Sentry storage)
#
#   1. generate the demo PKI with Jash's transport/cert_generator.py
#   2. start Anuvrat's Sentry over TLS 1.3 with client-cert REQUIRED
#   3. prove a client WITHOUT a cert is rejected at the TLS layer
#   4. run Anay's agent presenting Jash's client cert (SENTRY_URL=https://…)
#   5. benchmark the agent->Sentry ingest throughput over mTLS (integration/bench.py)
#   6. verify the hash chain [PASS]
#   7. validate a *received* heartbeat against Jash's own parser (three-way sync)
#
# Connects to https://127.0.0.1:PORT — the demo server cert's SAN includes
# 127.0.0.1, so no /etc/hosts entry is needed. (Use sentry.local if you prefer;
# it is also in the SAN.)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SENTRY_DIR="${REPO}/SentryP"
AGENT_DIR="${REPO}/agent/barbarika-agent"
PORT="${SENTRY_PORT:-8000}"
BASE_URL="https://127.0.0.1:${PORT}"
BENCH_N="${BENCH_N:-200}"

WORK="$(mktemp -d)"
CERTS="${WORK}/certs"
mkdir -p "${WORK}/mock_logs"
AGENT_BIN="${WORK}/barbarika-agent"
SENTRY_LOG="${WORK}/sentry.log"
AGENT_LOG="${WORK}/agent.log"

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

curl_mtls() { curl -sS --noproxy '*' --cacert "${CERTS}/demo-ca.crt" \
  --cert "${CERTS}/demo-client.crt" --key "${CERTS}/demo-client.key" "$@"; }

# --- 0. venv (fastapi + cryptography for the PKI + httpx for the bench) --------
VENV="${SENTRY_DIR}/.venv"
PY="${VENV}/bin/python"
if [[ ! -x "${PY}" ]] || ! "${PY}" -m pip --version >/dev/null 2>&1; then
  banner "Creating Sentry venv (first run)"
  rm -rf "${VENV}"
  python3 -m venv "${VENV}"
  "${PY}" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
"${PY}" -m pip -q install -r "${SENTRY_DIR}/backend/requirements.txt" cryptography >/dev/null

# --- 1. Generate Jash's demo PKI ----------------------------------------------
banner "Generating demo PKI (Jash: transport/cert_generator.py)"
"${PY}" "${REPO}/transport/cert_generator.py" --output-dir "${CERTS}" --force
ls "${CERTS}" | sed 's/^/  /'

# --- 2. Build the agent -------------------------------------------------------
banner "Building agent (Anay)"
( cd "${AGENT_DIR}" && go build -o "${AGENT_BIN}" . )
echo "  built ${AGENT_BIN}"

# --- 3. Start Sentry over mTLS ------------------------------------------------
banner "Starting Sentry over mTLS on ${BASE_URL} (client cert REQUIRED)"
if curl -sS --noproxy '*' -k "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "ERROR: ${BASE_URL} already serving — free port ${PORT} (SENTRY_PORT) and retry." >&2
  exit 1
fi
rm -f "${SENTRY_DIR}/data/barbarika.db"*
( cd "${SENTRY_DIR}" && PYTHONPATH="${SENTRY_DIR}" exec "${PY}" -m uvicorn backend.app.main:app \
    --host 127.0.0.1 --port "${PORT}" \
    --ssl-keyfile "${CERTS}/demo-server.key" --ssl-certfile "${CERTS}/demo-server.crt" \
    --ssl-ca-certs "${CERTS}/demo-ca.crt" --ssl-cert-reqs 2 \
    >"${SENTRY_LOG}" 2>&1 ) &
SENTRY_PID=$!

for _ in $(seq 1 40); do
  if curl_mtls "${BASE_URL}/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
printf '  health (with client cert): '; curl_mtls "${BASE_URL}/health"; echo

# --- 4. Negative test: no client cert must be rejected ------------------------
banner "Negative test: connect WITHOUT a client cert (must fail)"
if curl -sS --noproxy '*' --cacert "${CERTS}/demo-ca.crt" "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "  UNEXPECTED: server accepted a cert-less client — mTLS not enforced!" >&2
  exit 1
else
  echo "  OK: TLS layer rejected the cert-less client (mutual auth enforced)"
fi

# --- 5. Start the agent with Jash's client certificate ------------------------
banner "Starting agent over mTLS (presents Jash's demo-client cert)"
printf 'Aug 19 10:14:00 primary-srv-01 sshd[100]: Server listening on port 22\n' \
  > "${WORK}/mock_logs/auth.log"
: > "${WORK}/mock_logs/nginx_access.log"
( cd "${WORK}" \
    && SENTRY_URL="${BASE_URL}" AGENT_ID="primary-srv-01" \
       SENTRY_CA_CERT="${CERTS}/demo-ca.crt" \
       SENTRY_CLIENT_CERT="${CERTS}/demo-client.crt" \
       SENTRY_CLIENT_KEY="${CERTS}/demo-client.key" \
       exec "${AGENT_BIN}" >"${AGENT_LOG}" 2>&1 ) &
AGENT_PID=$!
sleep 2

# --- 6. Benchmark + heartbeat contract check ----------------------------------
banner "Benchmark: ${BENCH_N} events agent -> mTLS -> Sentry"
"${PY}" "${SCRIPT_DIR}/bench.py" \
  --base-url "${BASE_URL}" --certs "${CERTS}" \
  --auth-log "${WORK}/mock_logs/auth.log" --repo "${REPO}" -n "${BENCH_N}"

# --- 7. Verify the hash chain -------------------------------------------------
banner "Verify hash chain"
( cd "${SENTRY_DIR}" && PYTHONPATH="${SENTRY_DIR}" "${PY}" -m backend.scripts.verify_chain )

banner "mTLS END-TO-END OK"
echo "agent transport line:"; grep -m1 "Egress. Sentry transport" "${AGENT_LOG}" | sed 's/^/  /' || true
