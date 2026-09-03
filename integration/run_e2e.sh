#!/usr/bin/env bash
#
# Barbarika end-to-end connectivity demo (agent -> Sentry).
#
# Proves the joining contract in integration/CONTRACT.md:
#   1. starts Anuvrat's Sentry backend (SentryP) on :8000
#   2. runs Anay's Go agent (agent/barbarika-agent) against a mock auth.log
#   3. injects an SSH brute-force -> success -> sudo attack
#   4. shows the events landing in Sentry (GET /events)
#   5. verifies the hash chain          -> [PASS]
#   6. tampers with one row and re-verifies -> [FAIL]  (tamper-evidence)
#
# Plaintext HTTP for now; see CONTRACT.md "Next hardening" for mTLS.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SENTRY_DIR="${REPO}/SentryP"
AGENT_DIR="${REPO}/agent/barbarika-agent"
PORT="${SENTRY_PORT:-8000}"
BASE_URL="http://127.0.0.1:${PORT}"

WORK="$(mktemp -d)"
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

# --- 0. Python venv for Sentry -------------------------------------------------
VENV="${SENTRY_DIR}/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
  banner "Creating Sentry venv (first run)"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" -q install -r "${SENTRY_DIR}/backend/requirements.txt" httpx
fi
PY="${VENV}/bin/python"

# --- 1. Build the agent --------------------------------------------------------
banner "Building agent"
( cd "${AGENT_DIR}" && go build -o "${AGENT_BIN}" . )
echo "built ${AGENT_BIN}"

# --- 2. Start Sentry (clean chain) --------------------------------------------
banner "Starting Sentry on ${BASE_URL}"
if curl -fsS --noproxy '*' "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "ERROR: ${BASE_URL} is already serving — a previous run may be orphaned." >&2
  echo "       Free port ${PORT} (or set SENTRY_PORT) and retry." >&2
  exit 1
fi
rm -f "${SENTRY_DIR}/data/barbarika.db"*
# exec so ${SENTRY_PID} is the real uvicorn process (killable on cleanup).
( cd "${SENTRY_DIR}" && PYTHONPATH="${SENTRY_DIR}" exec "${PY}" -m uvicorn backend.app.main:app \
    --host 127.0.0.1 --port "${PORT}" >"${SENTRY_LOG}" 2>&1 ) &
SENTRY_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS --noproxy '*' "${BASE_URL}/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS --noproxy '*' "${BASE_URL}/health" && echo "  Sentry is up"

# --- 3. Seed a mock log, start the agent --------------------------------------
banner "Starting agent (SENTRY_URL=${BASE_URL})"
printf 'Aug 19 10:14:00 primary-srv-01 sshd[100]: Server listening on 0.0.0.0 port 22\n' \
  > "${WORK}/mock_logs/auth.log"
: > "${WORK}/mock_logs/nginx_access.log"
( cd "${WORK}" && SENTRY_URL="${BASE_URL}" AGENT_ID="primary-srv-01" \
    exec "${AGENT_BIN}" >"${AGENT_LOG}" 2>&1 ) &
AGENT_PID=$!
sleep 2

# --- 4. Inject an attack sequence ---------------------------------------------
banner "Injecting SSH brute-force -> success -> sudo (Category iii)"
AUTH="${WORK}/mock_logs/auth.log"
for i in 1 2 3 4 5; do
  printf 'Aug 19 10:15:0%d primary-srv-01 sshd[99%d]: Failed password for root from 185.220.101.4 port 41%02d ssh2\n' "$i" "$i" "$i" >> "${AUTH}"
  sleep 0.2
done
printf 'Aug 19 10:15:07 primary-srv-01 sshd[9907]: Accepted password for ubuntu from 185.220.101.4 port 4107 ssh2\n' >> "${AUTH}"
printf 'Aug 19 10:15:08 primary-srv-01 sudo:   ubuntu : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash\n' >> "${AUTH}"
echo "  injected 8 lines"
sleep 3

# --- 5. Read the events back from Sentry --------------------------------------
banner "Events stored in Sentry (GET /events)"
curl -fsS --noproxy '*' "${BASE_URL}/events" \
  | "${PY}" -c 'import sys,json; d=json.load(sys.stdin); print(f"  {len(d)} events stored"); [print("   -", e["sequence"], e["event_type"], "|", e["cur_hash"][:16]) for e in d]'

# --- 6. Verify the hash chain -------------------------------------------------
banner "Verify hash chain"
( cd "${SENTRY_DIR}" && PYTHONPATH="${SENTRY_DIR}" "${PY}" -m backend.scripts.verify_chain )

# --- 7. Tamper-evidence demo --------------------------------------------------
banner "Tamper one row, re-verify (expect [FAIL])"
"${PY}" - "$SENTRY_DIR" <<'PY'
import sys, sqlite3, pathlib
db = pathlib.Path(sys.argv[1]) / "data" / "barbarika.db"
con = sqlite3.connect(db)
con.execute("UPDATE events SET source='tampered' WHERE id=(SELECT MIN(id) FROM events)")
con.commit(); con.close()
print("  mutated source of the first event row")
PY
if ( cd "${SENTRY_DIR}" && PYTHONPATH="${SENTRY_DIR}" "${PY}" -m backend.scripts.verify_chain ); then
  echo "UNEXPECTED: verify passed after tamper"; exit 1
else
  echo "  tamper correctly detected (verify returned non-zero)"
fi

banner "END-TO-END OK"
echo "agent log tail:"; tail -n 4 "${AGENT_LOG}" | sed 's/^/  /'
