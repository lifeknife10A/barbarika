# Barbarika

Evidence-Preserving CERT-In Incident Readiness and Assisted Reporting Platform.
SIH 2026 — Team Barbarika, NMIMS MPSTME. Theme: Blockchain & Cybersecurity.

## Status

Pre-hackathon build phase. Target: have the full working prototype done before the 36-hour event
(internal registration filed 21 Aug 2026; Idea PPT due 30 Aug 2026; ideathon 12 Sept 2026).

## Layout

```
agent/        Go ingestion daemon (monitored host)
transport/    Shared mTLS config + heartbeat/watchdog
sentry/       FastAPI + SQLite WAL evidence vault (isolated host)
rules/        Detection schema + YAML rules + tests
dashboard/    React/Vite CISO dashboard
compliance/   PDF/email generation + demo attack scripts
docs/         Supporting notes specific to this codebase
```

Wider project research, the locked problem statement, the full architecture blueprint, and the
SIH pitch playbook live one level up in `../` (the SIH workspace).
