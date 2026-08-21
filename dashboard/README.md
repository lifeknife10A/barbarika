# Barbarika CISO Dashboard (`dashboard/`)

> **Role & Owner:** Pam (`pam-mt3dchpq`) / Nandini Chitlangia (Frontend & UI Lead)  
> **Tech Stack:** React 18 + Vite 6 + TypeScript + Tailwind CSS (managed strictly with **`pnpm`**)  
> **Theme:** Evidence-Preserving CERT-In Incident Readiness & Assisted Reporting (SIH 2026)

---

## Overview

The **Barbarika CISO Dashboard** is the command-and-control frontend for the Barbarika Incident Readiness Platform. It is designed to provide real-time situational awareness, enforce strict statutory deadlines under Section 70B(6) of the Information Technology Act 2000, visualize cryptographic evidence provenance chains, and facilitate assisted Annexure I reporting to CERT-In.

---

## Key Features & Compliance Alignment

### 1. 6-Hour Statutory Reporting Deadline Clock
- **Computed strictly from `noticed_at`** (not from a generic timer start).
- Tracks all 6 distinct statutory timestamps:
  1. `occurred_at` (Primary host timestamp)
  2. `detected_at` (Local Go daemon detection)
  3. `received_at` (Trusted wall-clock timestamp stamped on Sentry SQLite write)
  4. `noticed_at` (Incident awareness start)
  5. `confirmed_at` (Mandatory human reviewer sign-off)
  6. `reported_at` (Formal Annexure I submission drafting)
- Visual urgency indicators: Amber (< 3 hours remaining) & Red (< 1 hour remaining) with statutory compliance warnings citing Section 70B(7) penalties (up to ₹1 Crore / 1 year imprisonment).

### 2. Inverted Heartbeat Watchdog & Host Health Monitor
- **5-Second Sliding Window / 3-Miss Threshold (15s):**
  $$\text{HEALTHY} \xrightarrow{\text{3 missed heartbeats (15s)}} \text{TELEMETRY\_LOSS}$$
- **Zero Inbound Assurance:** Visual verification that the monitored primary host has 0 open listening ports and communicates outbound-only via TLS 1.3 mTLS.
- **Dead Man's Switch:**
  - **Case A (Isolated Network Drop):** Flags operational telemetry warning only without false compliance alarms.
  - **Case B (Adversarial Host Disruption):** Preceded by high-confidence intrusion activity within a 120s correlation window $\rightarrow$ flags **`SUSPECTED_HOST_COMPROMISE`** and surfaces a **Candidate Category (ii) — Compromise of Critical Systems** requiring mandatory human reviewer confirmation.

### 3. Interactive Evidence Provenance Graph (DAG)
- Traces the deterministic 4-stage chain:
  $$\text{Raw Telemetry Events (Hashes/Sig)} \longrightarrow \text{Fired Detection Rule} \longrightarrow \text{Statutory Category} \longrightarrow \text{Annexure I Form Fields}$$
- Clickable node inspector displaying raw JSON payloads, Ed25519 signature validation, and rule correlation logic.

### 4. Role-Gated Identifier Unmasking & Immutable Audit Trail
- Sensitive fields (source IPs, user accounts, file paths) are **masked by default** in the UI and encrypted at rest with AES-GCM.
- Unmasking is an authenticated, role-gated action requiring a reviewer PIN and mandatory regulatory justification.
- **Immutable Audit Trail view:** Permanently logs `Who`, `When`, `Target Field`, `Masked -> Unmasked Value`, `Reason`, and `IP Address`.

### 5. Tamper-Evident Evidence Vault & 1-Click Verification
- Inspects the append-only SQLite WAL hash chain:
  $$\text{RecordHash} = \text{SHA-256}(\text{DomainSeparator} \,\|\, \text{PrevHash} \,\|\, \text{Sequence} \,\|\, \text{ReceivedAt} \,\|\, \text{ExactEventBytes})$$
- **1-Click Verify Script Runner:** UI simulator displaying target verification output (illustrative example from architecture blueprint: `[PASS] 47 records | Valid Ed25519 signatures | Contiguous sequence | Receipt chain intact`; pending real measured results from `sentry/` integration).

### 6. CERT-In Annexure I Compliance & Draft Package
- Previews the auto-populated official CERT-In Annexure I reporting form.
- Formats draft email for `incident@cert-in.org.in`.
- **Human-in-the-loop Safeguard:** Explicitly non-transmitting; auto-drafts defensible compliance artifacts without auto-sending.

### 7. Full 20/20 Statutory Taxonomy
- Honest coverage display: **"20/20 statutory categories represented in schema, 3/20 live-detected"** (Category iii, Category iv, Category v, plus candidate Category ii).

---

## 3-Minute Stage Demo Controller

The dashboard includes a built-in stage controller with 4 test scenarios matching the hackathon blueprint:
1. **Path 1: Category (iii)** — SSH Brute-Force + Sudo Privilege Elevation
2. **Path 2: Category (iv)** — Nginx Exploit + fsnotify `/var/www` Defacement
3. **Path 3: Category (v)** — Rapid Bulk Encryption + Canary Tripwire Trigger
4. **Path 4: Candidate Category (ii)** — Dead Man Switch Host Disruption (Intrusion + 15s Flatline)
5. **Reset Baseline** — Clean state with 0 incidents, both nodes green, deadline on standby.

---

## Getting Started

### Prerequisites
- Node.js (v18+)
- **pnpm** (v9+)

### Installation
```bash
# Inside barbarika/dashboard:
pnpm install
```

### Running Development Server
```bash
pnpm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

### Building for Production
```bash
pnpm run build
```
Generates clean, optimized static production artifacts in `dist/`.
