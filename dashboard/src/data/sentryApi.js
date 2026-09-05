// ─────────────────────────────────────────────────────────────────────────────
// Thin client for the Sentry backend (../../sentry). Everything the dashboard
// shows that is real comes through here; the UI never talks to Sentry directly.
//
// Base URL: VITE_SENTRY_URL if set, else "/api" (the Vite dev-proxy forwards
// /api → the Sentry host, so the browser stays same-origin and needs no CORS
// and no mTLS client cert — Sentry runs dev-insecure/plaintext for the demo).
//
// Endpoint shapes mirror sentry/app/main.py + models.py:
//   GET  /health            → { status, journal_mode, events, incidents, rules_loaded, mtls }
//   GET  /events?limit=n    → EventOut[]  (masked by default)
//   GET  /incidents         → IncidentOut[]
//   GET  /events/stream     → SSE, messages named "event" and "incident"
// ─────────────────────────────────────────────────────────────────────────────

const BASE = (import.meta.env?.VITE_SENTRY_URL || '/api').replace(/\/$/, '');

async function getJSON(path, { timeoutMs = 4000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE}${path}`, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

export const getHealth = () => getJSON('/health');
export const getEvents = (limit = 200) => getJSON(`/events?limit=${limit}`);
export const getIncidents = () => getJSON('/incidents');
export const getHost = () => getJSON('/host'); // latest agent-host snapshot(s)

// Open the live SSE stream. Returns a close() fn. Sentry replays recent events
// then streams live `event` / `incident` messages.
export function openStream({ onEvent, onIncident, onOpen, onError }) {
  const es = new EventSource(`${BASE}/events/stream`);
  if (onOpen) es.onopen = onOpen;
  es.addEventListener('event', (e) => { try { onEvent?.(JSON.parse(e.data)); } catch { /* ignore */ } });
  es.addEventListener('incident', (e) => { try { onIncident?.(JSON.parse(e.data)); } catch { /* ignore */ } });
  if (onError) es.onerror = onError;
  return () => es.close();
}

// ── mappers: Sentry wire shapes → the dashboard's model shapes ────────────────

const hhmmss = (iso) => {
  const d = iso ? new Date(iso) : new Date();
  return Number.isNaN(d.getTime()) ? '--:--:--' : d.toTimeString().slice(0, 8);
};

// EventOut → a log-feed row. severity → level; source "<agent>/<log>" → service.
export function eventToRow(ev) {
  const sevToLevel = { info: 'info', warn: 'warn', critical: 'critical', emergency: 'critical' };
  const service = String(ev.source || '').split('/').pop() || 'log';
  const agent = ev.payload?.agent_id || String(ev.source || '').split('/')[0] || '—';
  return {
    id: ev.id ?? ev.seq ?? Math.random(),
    time: hhmmss(ev.received_at || ev.occurred_at),
    level: sevToLevel[ev.severity] || 'info',
    source: agent,
    service,
    message: ev.raw_message || `${ev.event_type} (${ev.category ?? 'uncategorised'})`,
    digest: (ev.row_hash || '').slice(0, 6) || '------',
    verified: !!ev.signature_verified,
    signer: ev.signer_identity || null,
  };
}

// IncidentOut → a compact incident record (CERT-In category + Anishka's rule).
export function incidentToRecord(inc) {
  return {
    id: inc.incident_uuid || inc.id,
    category: inc.category,
    ruleTitle: inc.rule_title,
    ruleId: inc.rule_id,
    eventIds: inc.event_ids || [],
    detectedAt: inc.detected_at,
    time: hhmmss(inc.detected_at || inc.created_at),
  };
}

// HostSnapshot → the System Health tiles + derived identity (real OS/kernel).
// The agent runs on the host, so these are the host's actual vitals — not sim.
const r1 = (n) => (n == null ? null : Math.round(n));
const gb = (mb) => (mb == null ? null : (mb / 1024));

export function hostToSystem(snap, prevTiles, prevIdentity) {
  const byId = Object.fromEntries((prevTiles || []).map((t) => [t.id, { ...t }]));
  if (byId.cpu && snap.cpu_percent != null) {
    byId.cpu.value = String(r1(snap.cpu_percent));
    byId.cpu.fill = Math.min(100, snap.cpu_percent);
    byId.cpu.meta = snap.load1 != null ? `load ${snap.load1.toFixed(2)}` : byId.cpu.meta;
  }
  if (byId.memory && snap.mem_total_mb) {
    byId.memory.value = gb(snap.mem_used_mb).toFixed(1);
    byId.memory.fill = Math.min(100, (snap.mem_used_mb / snap.mem_total_mb) * 100);
    const rss = snap.rss_mb != null ? ` · agent RSS ${r1(snap.rss_mb)} MB` : '';
    byId.memory.meta = `of ${gb(snap.mem_total_mb).toFixed(0)} GB${rss}`;
  }
  if (byId.daemon) {
    byId.daemon.value = 'Active';
    const up = snap.uptime_s != null ? ` · up ${Math.floor(snap.uptime_s / 3600)}h` : '';
    byId.daemon.meta = `${snap.agent_version || 'agent'}${up}`;
  }
  const identity = prevIdentity ? { ...prevIdentity, target: { ...prevIdentity.target } } : prevIdentity;
  if (identity) {
    if (snap.agent_id) identity.target.key = snap.agent_id;
    if (snap.os) identity.target.os = snap.os;
    if (snap.kernel) identity.target.kernel = snap.kernel;
  }
  return { tiles: Object.values(byId), identity };
}

// /health → the two Sentry health tiles we can actually source live.
export function healthToSentryTiles(h, prevTiles) {
  const byId = Object.fromEntries((prevTiles || []).map((t) => [t.id, { ...t }]));
  if (byId.chain) {
    byId.chain.value = String(h.events ?? byId.chain.value);
    byId.chain.meta = `SHA-256 · ${h.rules_loaded ?? '?'} rules loaded`;
  }
  if (byId.vault) {
    byId.vault.value = String(h.journal_mode || 'WAL').toUpperCase();
    byId.vault.unit = '';
    byId.vault.meta = `${h.incidents ?? 0} incidents · append-only`;
  }
  if (byId.watchdog) {
    byId.watchdog.meta = `mTLS: ${h.mtls || 'n/a'} · live`;
  }
  return Object.values(byId);
}
