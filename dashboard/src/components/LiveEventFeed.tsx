import React, { useState } from 'react';
import { FileText, Search, Lock, Unlock, ShieldAlert, Activity, ChevronRight, ChevronDown, CheckCircle2 } from 'lucide-react';
import { TelemetryEvent, Severity } from '../types';

interface LiveEventFeedProps {
  events: TelemetryEvent[];
  onOpenUnmask: (field: string, entityId: string, maskedVal: string, realVal: string) => void;
}

export const LiveEventFeed: React.FC<LiveEventFeedProps> = ({
  events,
  onOpenUnmask,
}) => {
  const [filterType, setFilterType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string | number | null>(null);

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'emergency':
        return <span className="px-2 py-0.5 rounded bg-rose-600 text-white font-bold text-[10px] uppercase font-mono-code animate-pulse">EMERGENCY</span>;
      case 'critical':
        return <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px] uppercase font-mono-code border border-rose-500/30">CRITICAL</span>;
      case 'warn':
        return <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold text-[10px] uppercase font-mono-code border border-amber-500/30">WARN</span>;
      default:
        return <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-medium text-[10px] uppercase font-mono-code">INFO</span>;
    }
  };

  const filteredEvents = events.filter(evt => {
    if (filterType === 'auth' && !evt.source.includes('auth') && !evt.event_type.includes('ssh')) return false;
    if (filterType === 'nginx' && !evt.source.includes('nginx')) return false;
    if (filterType === 'fsnotify' && !evt.source.includes('fsnotify') && !evt.event_type.includes('file')) return false;
    if (filterType === 'heartbeat' && evt.event_type !== 'heartbeat') return false;
    if (filterType === 'critical' && evt.severity !== 'critical' && evt.severity !== 'emergency') return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        evt.event_type.toLowerCase().includes(q) ||
        evt.source.toLowerCase().includes(q) ||
        JSON.stringify(evt.payload).toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="glass-panel rounded-xl p-6 border border-cyber-border">
      
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 mb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              REAL-TIME TELEMETRY FEED (SENTRY INGESTION)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Streaming Ed25519-signed journald, auth, nginx, and fsnotify events verified into SQLite WAL.
          </p>
        </div>

        {/* Filter Badges */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs font-medium">
          {['all', 'auth', 'nginx', 'fsnotify', 'heartbeat', 'critical'].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilterType(tab)}
              className={`px-2.5 py-1 rounded-md capitalize transition ${
                filterType === tab
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Search Input */}
      <div className="relative mb-4">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
        <input
          type="text"
          placeholder="Filter by event type, IP, source, or payload keyword..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-[#05070a] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono-code placeholder:text-slate-600"
        />
      </div>

      {/* Event List */}
      <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-500">
            No telemetry records matching current filter.
          </div>
        ) : (
          filteredEvents.map((evt) => {
            const isExpanded = expandedId === evt.id;
            const hasIp = evt.payload?.src_ip;
            const maskedIp = evt.masked_fields?.src_ip || '203.0.***.***';

            return (
              <div
                key={evt.id}
                className="rounded-lg bg-cyber-card border border-cyber-border transition hover:border-slate-700"
              >
                <div
                  onClick={() => setExpandedId(isExpanded ? null : evt.id)}
                  className="p-3 flex items-center justify-between gap-3 cursor-pointer text-xs"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <button className="text-slate-500 hover:text-slate-300">
                      {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>
                    {getSeverityBadge(evt.severity)}
                    <span className="font-mono-code text-blue-400 font-semibold truncate max-w-[150px] sm:max-w-[200px]">
                      {evt.event_type}
                    </span>
                    <span className="text-slate-500 font-mono-code hidden md:inline">
                      [{evt.source}]
                    </span>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {hasIp && (
                      <div className="flex items-center gap-1.5 font-mono-code text-[11px] bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                        <Lock className="w-3 h-3 text-amber-400" />
                        <span className="text-amber-300">{maskedIp}</span>
                      </div>
                    )}
                    <span className="text-slate-400 font-mono-code text-[11px]">
                      {new Date(evt.received_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 bg-[#070a10] border-t border-slate-800 text-xs space-y-3 font-mono-code">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-400">
                      <div>
                        <span className="text-slate-500 block text-[10px]">Event ID:</span>
                        <span className="text-slate-200">{evt.event_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Sequence #:</span>
                        <span className="text-slate-200">#{evt.sequence || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Signature:</span>
                        <span className="text-emerald-400 font-bold">Ed25519 Valid</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-400 text-[11px] block font-sans font-semibold mb-1">
                        Structured Payload:
                      </span>
                      <pre className="p-3 rounded bg-[#030407] border border-slate-800/80 text-slate-300 text-[11px] overflow-x-auto">
                        {JSON.stringify(evt.payload, null, 2)}
                      </pre>
                    </div>

                    {hasIp && (
                      <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                        <span className="text-slate-400 text-[11px] font-sans">
                          Sensitive Identifier (AES-GCM Masked at rest)
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenUnmask('src_ip', String(evt.id), maskedIp, evt.payload.src_ip);
                          }}
                          className="flex items-center gap-1 px-3 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold border border-amber-500/40"
                        >
                          <Unlock className="w-3.5 h-3.5" />
                          <span>Unmask Identifier (Audited)</span>
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

    </div>
  );
};
