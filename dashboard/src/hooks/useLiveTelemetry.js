import { useEffect, useRef, useState } from 'react';
import { systemModel } from '../data/systemModel';
import {
  getHealth, getEvents, getIncidents, getHost, openStream,
  eventToRow, incidentToRecord, healthToSentryTiles, hostToSystem,
} from '../data/sentryApi';

// Apply the latest host snapshot (if any) onto the System Health tiles + identity.
function applyHost(m, hosts) {
  const snap = Array.isArray(hosts) ? hosts[0] : hosts;
  if (!snap) return m;
  const { tiles, identity } = hostToSystem(snap, m.systemHealth.tiles, m.identity);
  return { ...m, systemHealth: { ...m.systemHealth, tiles }, identity };
}

const clone = (o) => JSON.parse(JSON.stringify(o));
const MAX_ROWS = 300;

// Roll a list of ISO timestamps into 30 one-minute EPM buckets ending "now".
function epmBuckets(times) {
  const now = Date.now();
  const b = new Array(30).fill(0);
  for (const iso of times) {
    const idx = Math.floor((now - new Date(iso).getTime()) / 60000);
    if (idx >= 0 && idx < 30) b[29 - idx] += 1;
  }
  return b;
}

/**
 * Starts from the mock model (so the UI always renders), then overlays live
 * Sentry data when the backend is reachable. Returns { model, live }.
 *   live = 'connecting' | 'live' | 'offline'
 */
export function useLiveTelemetry() {
  const [model, setModel] = useState(() => clone(systemModel));
  const [live, setLive] = useState('connecting');
  const evTimes = useRef([]); // ISO strings of recent event receipts, for EPM
  const seen = useRef(new Set()); // event ids already shown (SSE replays overlap the initial fetch)

  useEffect(() => {
    let cancelled = false;
    let closeStream = () => {};
    let healthTimer;

    const pushEvent = (ev) => {
      const key = ev.id ?? ev.seq;
      if (key != null && seen.current.has(key)) return; // dedupe replayed events
      if (key != null) seen.current.add(key);
      const row = eventToRow(ev);
      evTimes.current = [ev.received_at || new Date().toISOString(), ...evTimes.current].slice(0, 2000);
      setModel((m) => {
        const logs = [row, ...m.logs].slice(0, MAX_ROWS);
        const history = epmBuckets(evTimes.current);
        return { ...m, logs, epm: { ...m.epm, history, current: history[history.length - 1] } };
      });
    };

    const pushIncident = (inc) => setModel((m) => ({
      ...m, incidents: [incidentToRecord(inc), ...(m.incidents || [])].slice(0, 50),
    }));

    async function boot() {
      try {
        const [health, events, incidents, hosts] = await Promise.all([
          getHealth(), getEvents(200), getIncidents(), getHost().catch(() => []),
        ]);
        if (cancelled) return;
        evTimes.current = events.map((e) => e.received_at || e.occurred_at).filter(Boolean);
        events.forEach((e) => { const k = e.id ?? e.seq; if (k != null) seen.current.add(k); });
        const history = epmBuckets(evTimes.current);
        setModel((m) => applyHost({
          ...m,
          logs: events.map(eventToRow).slice(0, MAX_ROWS),
          incidents: incidents.map(incidentToRecord),
          epm: { ...m.epm, history, current: history[history.length - 1] },
          sentryHealth: { ...m.sentryHealth, tiles: healthToSentryTiles(health, m.sentryHealth.tiles) },
        }, hosts));
        setLive('live');

        closeStream = openStream({
          onEvent: pushEvent,
          onIncident: pushIncident,
          onError: () => !cancelled && setLive('offline'),
          onOpen: () => !cancelled && setLive('live'),
        });

        healthTimer = setInterval(async () => {
          try {
            const [h, hosts] = await Promise.all([getHealth(), getHost().catch(() => [])]);
            if (cancelled) return;
            setModel((m) => applyHost(
              { ...m, sentryHealth: { ...m.sentryHealth, tiles: healthToSentryTiles(h, m.sentryHealth.tiles) } },
              hosts,
            ));
          } catch { setLive('offline'); }
        }, 5000);
      } catch {
        if (!cancelled) setLive('offline'); // Sentry not reachable → keep mock
      }
    }

    boot();
    return () => { cancelled = true; closeStream(); clearInterval(healthTimer); };
  }, []);

  return { model, live };
}
