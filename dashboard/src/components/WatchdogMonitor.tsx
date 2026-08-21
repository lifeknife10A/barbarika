import React from 'react';
import { Activity, ShieldCheck, Radio, Server } from 'lucide-react';
import { NodeHealth } from '../types';

interface WatchdogMonitorProps {
  health: NodeHealth;
}

export const WatchdogMonitor: React.FC<WatchdogMonitorProps> = ({ health }) => {
  const { primary_agent, sentry_host } = health;
  const missedCount = primary_agent.missed_count;
  const isHealthy = sentry_host.watchdog_state === 'HEALTHY';
  const isTelemetryLoss = sentry_host.watchdog_state === 'TELEMETRY_LOSS';
  const isCompromise = sentry_host.watchdog_state === 'SUSPECTED_HOST_COMPROMISE';

  return (
    <div className="glass-panel rounded-xl p-5 border border-cyber-border">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Radio className={`w-4 h-4 ${isHealthy ? 'text-emerald-400 animate-pulse' : 'text-rose-400'}`} />
          <h3 className="font-bold text-slate-100 text-sm tracking-wide">
            INVERTED HEARTBEAT WATCHDOG & HOST MONITOR
          </h3>
        </div>
        <span className="text-[11px] font-mono-code text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700">
          5s Window / 3-Miss Threshold
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Card 1: Primary Host Architecture */}
        <div className="p-3.5 rounded-lg bg-cyber-card border border-cyber-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-blue-400" />
                Monitored Primary Host
              </span>
              <span className={`text-[10px] font-mono-code font-bold px-2 py-0.5 rounded ${
                primary_agent.status === 'ONLINE' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}>
                {primary_agent.status}
              </span>
            </div>
            <div className="space-y-1.5 text-xs text-slate-400 font-mono-code">
              <div className="flex justify-between">
                <span>Daemon Footprint:</span>
                <span className="text-slate-200">{primary_agent.rss_mb.toFixed(1)} MB RSS</span>
              </div>
              <div className="flex justify-between">
                <span>Inbound Listeners:</span>
                <span className="text-emerald-400 font-bold">0 (ZERO_INBOUND)</span>
              </div>
              <div className="flex justify-between">
                <span>Egress Transport:</span>
                <span className="text-blue-400">mTLS 1.3 Outbound</span>
              </div>
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-slate-800 flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Attack Surface:</span>
            <span className="text-slate-300 font-medium">No listening port exposure</span>
          </div>
        </div>

        {/* Card 2: 5-Second Heartbeat Sliding Window */}
        <div className="p-3.5 rounded-lg bg-cyber-card border border-cyber-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              Signed Heartbeat Feed
            </span>
            <span className="text-[11px] font-mono-code text-slate-400">
              Seq #{primary_agent.heartbeat_seq}
            </span>
          </div>

          {/* Missed Heartbeats 3-Step Meter */}
          <div className="space-y-2 my-2.5">
            <div className="flex justify-between text-[11px] font-mono-code">
              <span className="text-slate-400">Missed Pings:</span>
              <span className={missedCount >= 3 ? 'text-rose-400 font-bold' : missedCount > 0 ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                {missedCount} / 3 (15s threshold)
              </span>
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              <div className={`h-2 rounded ${missedCount >= 1 ? 'bg-amber-500' : 'bg-slate-800'}`}></div>
              <div className={`h-2 rounded ${missedCount >= 2 ? 'bg-amber-500' : 'bg-slate-800'}`}></div>
              <div className={`h-2 rounded ${missedCount >= 3 ? 'bg-rose-500 animate-pulse' : 'bg-slate-800'}`}></div>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 mt-2">
            Last seen: <span className="font-mono-code text-slate-300">{new Date(primary_agent.last_heartbeat_at).toLocaleTimeString()}</span>
          </div>
        </div>

        {/* Card 3: Watchdog State Machine & 120s Window */}
        <div className={`p-3.5 rounded-lg border transition-all ${
          isCompromise ? 'bg-rose-950/20 border-rose-500/60' :
          isTelemetryLoss ? 'bg-amber-950/20 border-amber-500/60' :
          'bg-cyber-card border-cyber-border'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
              Watchdog State Machine
            </span>
            <span className={`text-[10px] font-mono-code font-bold px-2 py-0.5 rounded ${
              isCompromise ? 'bg-rose-500/30 text-rose-300 animate-pulse' :
              isTelemetryLoss ? 'bg-amber-500/30 text-amber-300' :
              'bg-emerald-500/20 text-emerald-300'
            }`}>
              {sentry_host.watchdog_state}
            </span>
          </div>

          <div className="space-y-1.5 text-xs text-slate-400 font-mono-code">
            <div className="flex justify-between">
              <span>Correlation Window:</span>
              <span className={sentry_host.correlation_window_active ? 'text-rose-400 font-bold animate-pulse' : 'text-slate-300'}>
                {sentry_host.correlation_window_active ? `${sentry_host.correlation_window_seconds_left}s ACTIVE` : 'INACTIVE (120s)'}
              </span>
            </div>
            <div className="flex justify-between">
              <span>Dead Man Switch:</span>
              <span className="text-slate-200">Pre-Intrusion Link</span>
            </div>
          </div>

          <p className="text-[10px] text-slate-400 mt-2 leading-relaxed">
            {isCompromise
              ? 'Telemetry loss preceded by intrusion within 120s window. Candidate Cat (ii) surfaced.'
              : isTelemetryLoss
              ? 'Network loss with zero prior attack signatures. Flagged as operational warning.'
              : 'Continuous Ed25519-signed telemetry stream verified.'}
          </p>
        </div>

      </div>
    </div>
  );
};
