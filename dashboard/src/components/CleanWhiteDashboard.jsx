import { useMemo } from 'react';
import {
  Cpu, HardDrive, Radio, Clock, Server, Layers, Search,
} from 'lucide-react';
import { identityLabel } from '../data/systemModel';
import { useLiveTelemetry } from '../hooks/useLiveTelemetry';

const LIVE_DOT = { live: 'bg-emerald-500', connecting: 'bg-amber-400', offline: 'bg-slate-300' };
const LIVE_LABEL = { live: 'live', connecting: 'connecting…', offline: 'offline · mock' };

// Icon registry — tiles reference icons by key in the model, never by import here.
const ICONS = { cpu: Cpu, memory: HardDrive, daemon: Radio, watchdog: Clock, vault: Server, chain: Layers };

// Level → dot colour (single place; the feed never hard-codes a colour).
const LEVEL_DOT = {
  info: 'bg-slate-300', notice: 'bg-sky-400', warn: 'bg-amber-400', critical: 'bg-red-500',
};
const STATE_DOT = { healthy: 'bg-emerald-500', warning: 'bg-amber-500', critical: 'bg-red-500' };

// ── tiny inline area chart (auto-scales to its own data) ─────────────────────
function areaPath(series, w, h, pad = 2) {
  const max = Math.max(...series, 1);
  const n = series.length;
  const x = (i) => (n === 1 ? 0 : (i / (n - 1)) * (w - pad * 2) + pad);
  const y = (v) => h - pad - (v / max) * (h - pad * 2);
  const line = series.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return { line, fill: `${line} L${(w - pad).toFixed(1)},${h} L${pad},${h} Z` };
}

function Sparkline({ series, stroke = '#0ea5e9', fill = 'rgba(14,165,233,0.10)', h = 44 }) {
  const w = 320;
  const { line, fill: fillPath } = useMemo(() => areaPath(series, w, h), [series, h]);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="w-full" style={{ height: h }}>
      <path d={fillPath} fill={fill} />
      <path d={line} fill="none" stroke={stroke} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// ── health tile ──────────────────────────────────────────────────────────────
function Tile({ tile }) {
  const Icon = ICONS[tile.icon] || Cpu;
  const c = tile.accent || '#2a78d6';
  return (
    <div className="flex-1 rounded-lg bg-white border border-slate-200/80 p-3" style={{ boxShadow: `inset 3px 0 0 ${c}` }}>
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
        <span className="inline-flex items-center justify-center w-5 h-5 rounded-md" style={{ background: `${c}1f`, color: c }}>
          <Icon className="w-3 h-3" />
        </span>
        {tile.label}
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-2xl font-bold text-slate-900 leading-none tabular-nums">{tile.value}</span>
        {tile.unit && <span className="text-xs font-medium text-slate-400">{tile.unit}</span>}
      </div>
      <div className="mt-2 h-1 rounded-full bg-slate-200 overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${tile.fill}%`, background: c }} />
      </div>
      <div className="mt-2 text-[10px] font-mono text-slate-400 truncate">{tile.meta}</div>
    </div>
  );
}

// ── health card (System / Sentry) ────────────────────────────────────────────
function HealthCard({ title, name, subtitle, state, tiles }) {
  return (
    <section className="flex-1 rounded-xl bg-white border border-slate-200 shadow-sm p-4">
      <div className="flex items-center gap-2.5 mb-3">
        <span className={`w-2 h-2 rounded-full ${STATE_DOT[state] || 'bg-slate-300'}`} />
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">{title}</h2>
            <span className="text-[11px] font-mono text-slate-800 font-semibold truncate">{name}</span>
          </div>
          <div className="text-[10px] font-mono text-slate-400 truncate">{subtitle}</div>
        </div>
      </div>
      <div className="flex gap-2.5">
        {tiles.map((t) => <Tile key={t.id} tile={t} />)}
      </div>
    </section>
  );
}

// ── incoming log feed (scrollable, minimal) ──────────────────────────────────
function LogFeed({ logs }) {
  return (
    <section className="flex flex-col min-h-0 rounded-xl bg-white border border-slate-200 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200">
        <h3 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">Incoming Log Feed</h3>
        <div className="flex items-center gap-1.5 text-slate-400 border border-slate-200 rounded-md px-2 py-1">
          <Search className="w-3 h-3" />
          <input
            className="w-28 bg-transparent text-[11px] outline-none placeholder:text-slate-400"
            placeholder="filter…" aria-label="Filter logs"
          />
        </div>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-slate-100">
        {logs.map((row) => (
          <div key={row.id} className="flex items-center gap-3 px-4 py-2 hover:bg-slate-50/80">
            <span className="font-mono text-[11px] text-slate-400 tabular-nums w-14 shrink-0">{row.time}</span>
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${LEVEL_DOT[row.level] || 'bg-slate-300'}`} />
            <span className="font-mono text-[11px] text-slate-500 w-16 shrink-0 truncate">{row.service}</span>
            <span className="text-[12px] text-slate-700 flex-1 min-w-0 truncate">{row.message}</span>
            <span className="font-mono text-[11px] text-slate-400 tabular-nums w-28 shrink-0 truncate hidden lg:block">{row.source}</span>
            <span className="font-mono text-[10px] text-slate-400 bg-slate-100 rounded px-1.5 py-0.5 shrink-0 hidden md:block">{row.digest}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

// ── chart card ────────────────────────────────────────────────────────────────
function ChartCard({ title, right, children, className = '' }) {
  return (
    <section className={`rounded-xl bg-white border border-slate-200 shadow-sm p-4 flex flex-col ${className}`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-[11px] font-bold uppercase tracking-widest text-slate-500">{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}

export default function CleanWhiteDashboard() {
  const { model: m, live } = useLiveTelemetry();

  return (
    <div className="h-full min-h-0 flex flex-col gap-3 bg-slate-100/60 rounded-lg p-3 overflow-hidden">

      {/* live/offline indicator (offline ⇒ the mock data below) */}
      <div className="flex items-center gap-1.5 px-1 -mb-1">
        <span className={`w-1.5 h-1.5 rounded-full ${LIVE_DOT[live]}`} />
        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Sentry feed · {LIVE_LABEL[live]}</span>
      </div>

      {/* ── Row 1: dual health (derived identity, no status-word badges) ── */}
      <div className="flex gap-3">
        <HealthCard
          title="System Health"
          name={m.identity.target.key}
          subtitle={`${m.identity.target.role} · ${m.identity.target.os}`}
          state={m.systemHealth.state}
          tiles={m.systemHealth.tiles}
        />
        <HealthCard
          title="Sentry Health"
          name={m.identity.sentry.key}
          subtitle={`${m.identity.sentry.enclave} · ${m.identity.sentry.engine}`}
          state={m.sentryHealth.state}
          tiles={m.sentryHealth.tiles}
        />
      </div>

      {/* ── Row 2: charts (left) + scrollable feed (right, fills height) ── */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3">

        {/* Left column: EPM + secondary host-load chart */}
        <div className="lg:col-span-5 flex flex-col gap-3 min-h-0">
          <ChartCard
            title={`Events / minute · ${m.epm.spanLabel}`}
            className="flex-1 min-h-0"
            right={
              <span className="text-sm font-bold text-slate-900 tabular-nums">
                {m.epm.current}<span className="text-[11px] font-medium text-slate-400 ml-1">{m.epm.unit}</span>
              </span>
            }
          >
            <div className="flex-1 min-h-0 flex flex-col justify-end">
              <Sparkline series={m.epm.history} h={120} />
              <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span>−{m.epm.history.length}m</span>
                <span>spike threshold {m.epm.spikeThreshold.toLocaleString()} {m.epm.unit}</span>
                <span>now</span>
              </div>
            </div>
          </ChartCard>

          <ChartCard
            title={`${m.hostLoad.title} · ${m.hostLoad.spanLabel}`}
            right={
              <span className="text-sm font-bold text-slate-900 tabular-nums">
                {m.hostLoad.series.at(-1)}<span className="text-[11px] font-medium text-slate-400 ml-1">{m.hostLoad.unit}</span>
              </span>
            }
          >
            <Sparkline series={m.hostLoad.series} h={48} stroke="#6366f1" fill="rgba(99,102,241,0.10)" />
          </ChartCard>
        </div>

        {/* Right column: the log feed owns the whole lower section, scrollable */}
        <div className="lg:col-span-7 flex flex-col min-h-0">
          <LogFeed logs={m.logs} />
        </div>
      </div>

      {/* derived footer identity — placeholder format "<host> @ <sentry>" */}
      <div className="text-[10px] font-mono text-slate-400 px-1">{identityLabel(m)}</div>
    </div>
  );
}
