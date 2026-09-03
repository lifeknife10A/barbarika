# Barbarika Sentry – Working Prototype Guide

This document walks you through the **complete end‑to‑end prototype** that
Anuvrat Tripathi is responsible for (FastAPI backend, SQLite WAL storage, and
cryptographic hash‑chain integrity). It also provides quick commands you can
run to verify that everything is working on your own machine.

---

## 1️⃣  Project layout
```
backend/
│
├─ app/                     # FastAPI application code
│   ├─ __init__.py
│   ├─ main.py               # FastAPI instance – registers routers
│   ├─ database.py           # SQLite engine (WAL mode) + session factory
│   ├─ models.py             # ORM definitions: Event & Heartbeat
│   ├─ schemas.py            # Pydantic request/response models
│   ├─ services/
│   │   ├─ __init__.py       # re‑exports hash_chain
│   │   └─ hash_chain.py     # SHA‑256 chaining helper
│   └─ routes/
│       ├─ __init__.py
│       ├─ health.py          # /health + optional debug endpoint
│       ├─ events.py          # /events CRUD + hash‑chain handling
│       └─ heartbeat.py       # /heartbeat endpoint
│
├─ scripts/
│   └─ verify_chain.py       # CLI verifier – walks the DB and checks hashes
│
├─ data/                     # runtime data (created on first run)
│   └─ barbarika.db           # SQLite DB (WAL mode) — single authoritative store
│
└─ requirements.txt           # fastapi, uvicorn, sqlalchemy, aiosqlite, pydantic
```
All code lives **inside the `backend` package**, keeping the prototype self‑
contained.

---

## 2️⃣  Quick‑start – get the prototype running locally
### 2.1  Prerequisites
* Windows 10/11 with PowerShell.
* Python 3.12 (the `venv` we created uses the system interpreter).

### 2.2  Steps (copy‑paste into PowerShell)
```powershell
# 1️⃣ Navigate to the repo root (you should already be here)
cd "C:\Users\Anuvrat\Desktop\S5\1. General\SIH"

# 2️⃣ Create a virtual environment (if you haven’t yet)
python -m venv .venv

# 3️⃣ Install dependencies (requires internet – sandbox will prompt for
#    escalation if needed)
& ".\.venv\Scripts\pip.exe" install -r backend\requirements.txt

# 4️⃣ Run the FastAPI server – it will listen on port 8003 (any free port works)
& ".\.venv\Scripts\python.exe" -m uvicorn backend.app.main:app --reload --port 8003
```
You should see something like:
```
INFO:     Uvicorn running on http://127.0.0.1:8003 (Press CTRL+C to quit)
INFO:     Application startup complete.
```
Leave this terminal open – the API is now serving requests.

---

## 3️⃣  Functional sanity‑check – how to test the prototype
Open a **second** PowerShell window (keep the server running in the first one).
Run the commands exactly as shown.

### 3.1  Health check (expect `{ "status": "ok" }`)
```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8003/health -UseBasicParsing
```
A `200 OK` response with the JSON payload should be printed.

### 3.2  List events (initially empty)
```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8003/events -Method GET -UseBasicParsing
```
Response body will be `[]`.

### 3.3  Post a sample event
```powershell
$payload = '{"agent_id":"demo-agent","sequence":1,"timestamp":"2026-09-04T12:00:00Z","source":"auth.log","event_type":"ssh_failed_login","payload":{"ip":"10.0.0.1"}}'
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8003/events -Body $payload -ContentType 'application/json'
```
The server returns the stored object, including `cur_hash` (the hash‑chain
fingerprint).

### 3.4  Verify the event is stored
```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8003/events -Method GET -UseBasicParsing
```
You’ll see a JSON array containing the record you just posted.

### 3.5  Run the **hash‑chain verification script**
```powershell
& ".\.venv\Scripts\python.exe" -m backend.scripts.verify_chain
```
Expected output (with a single record):
```
[PASS] 1 records verified, 0 tampering detected
```
If you manually alter a stored SQLite row and run the script again, you’ll get a
`[FAIL]` with details – that demonstrates the tamper‑evidence property. SQLite is
the single authoritative store; there is no separate NDJSON copy.

---

## 4️⃣  Optional – heartbeat endpoint
```powershell
$hb = '{"agent_id":"demo-agent","boot_id":"boot-123","sequence":1,"sent_at_utc":"2026-09-04T12:00:30Z","last_event_sequence":1,"last_event_hash":"<hash-from-previous-response>","agent_health":"healthy","signature":"deadbeef"}'
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8003/heartbeat -Body $hb -ContentType 'application/json'
```
A `202` response with `{"detail":"heartbeat recorded"}` confirms storage.

---

## 5️⃣  What’s left – final polish
| Item | Status | What to do |
|------|--------|------------|
| **Hash‑chain verification script** | ✅ Implemented (`backend/scripts/verify_chain.py`) | Run as shown in section 3.5 |
| **Code lint / formatting** | ⏳ Optional | Run `ruff format .` or `black .` – no functional impact |
| **Tests** | ⏳ Optional | Add pytest files under `backend/tests/` for event ingestion & verification |
| **Documentation** | ✅ Added (`PROTOTYPE.md`) | Read this file for the full walk‑through |

When those optional items are done, the prototype satisfies **all** of the
backend/storage requirements for the Barbarika hackathon.

---

## 6️⃣  TL;DR – one‑liner to start the server
```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn backend.app.main:app --reload --port 8003
```
Then use the `Invoke‑WebRequest` / `Invoke‑RestMethod` commands from section 3 to
exercise health, events, and verification.

---

**Enjoy building the rest of the system!** If you’d like the optional test suite
or a formatter config, just let me know and I’ll add the files.
