import React, { useState } from 'react';
import { 
  Search, 
  Hash, 
  CheckCircle2, 
  Terminal,
  Filter 
} from 'lucide-react';

export default function LiveIngestFeed({ 
  events = [], 
  selectedEventId, 
  onSelectEvent, 
  isMasked 
}) {
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredEvents = events.filter((ev) => {
    if (activeFilter === 'AUTH' && ev.source !== 'auth.log') return false;
    if (activeFilter === 'NGINX' && !ev.source.includes('nginx')) return false;
    if (activeFilter === 'JOURNAL' && ev.source !== 'journald' && ev.source !== 'systemd-journal') return false;
    if (activeFilter === 'CRITICAL' && ev.severity !== 'CRITICAL' && ev.severity !== 'ALERT') return false;
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const rawText = (isMasked ? ev.redactedRaw : ev.raw) || '';
      return (
        rawText.toLowerCase().includes(term) ||
        String(ev.id).includes(term) ||
        ev.source.toLowerCase().includes(term) ||
        ev.facility.toLowerCase().includes(term)
      );
    }
    return true;
  });

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-950/60 text-rose-300 border-rose-800/80 font-bold';
      case 'ALERT':
        return 'bg-amber-950/60 text-amber-300 border-amber-800/80 font-bold';
      case 'WARN':
        return 'bg-amber-950/30 text-amber-300/90 border-amber-900/40 font-medium';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800 font-normal';
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-[#090d16] flex flex-col h-full overflow-hidden">
      
      {/* Header Bar */}
      <div className="p-3 border-b border-slate-800/80 bg-[#070b13] flex items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-2 font-mono">
          <Terminal className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Live Ingestion Stream
          </h3>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
            {events.length} logs
          </span>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1 font-mono text-[10px]">
          {['ALL', 'AUTH', 'NGINX', 'CRITICAL'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveFilter(tab)}
              className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                activeFilter === tab
                  ? 'bg-sky-950 text-sky-300 border border-sky-800/80 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Search Input Bar */}
      <div className="px-3 py-1.5 border-b border-slate-800/60 bg-[#06090f] flex items-center gap-2 shrink-0">
        <Search className="w-3.5 h-3.5 text-slate-500 shrink-0" />
        <input
          type="text"
          placeholder="Filter telemetry logs..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full text-[11px] font-mono bg-transparent border-none text-slate-200 placeholder-slate-600 focus:outline-none"
        />
      </div>

      {/* Log Feed Table (Internally scrollable, does not scroll page) */}
      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 font-mono text-xs">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs">
            No events match current filter.
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const isSelected = selectedEventId === ev.id;
            return (
              <div
                key={ev.id}
                onClick={() => onSelectEvent(ev)}
                className={`p-2.5 transition-colors cursor-pointer hover:bg-slate-900/60 flex items-start gap-2.5 ${
                  isSelected ? 'bg-sky-950/30 border-l-2 border-sky-400' : ''
                } ${ev.severity === 'CRITICAL' ? 'bg-rose-950/15' : ''}`}
              >
                {/* Time and ID */}
                <div className="w-14 shrink-0 text-[10px] text-slate-400">
                  <span className="text-slate-500 block">#{ev.id}</span>
                  <span className="text-slate-300">{ev.time}</span>
                </div>

                {/* Severity Badge */}
                <div className="shrink-0 pt-0.5">
                  <span className={`text-[8px] uppercase px-1.5 py-0.2 rounded border ${getSeverityBadge(ev.severity)}`}>
                    {ev.severity}
                  </span>
                </div>

                {/* Facility */}
                <div className="w-16 shrink-0 text-[10px] text-slate-400 truncate">
                  <span className="text-sky-400 font-semibold block">{ev.facility}</span>
                  <span className="text-slate-500 text-[9px] block truncate">{ev.source}</span>
                </div>

                {/* Payload */}
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] text-slate-200 leading-snug break-all">
                    {isMasked ? ev.redactedRaw : ev.raw}
                  </p>
                  <div className="mt-1 flex items-center gap-2 text-[9px] text-slate-500">
                    <span>{ev.hash}</span>
                    <span>•</span>
                    <span className="text-emerald-400">Ed25519 Verified</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Footer Strip */}
      <div className="p-2 border-t border-slate-800/80 bg-[#070b13] text-[10px] font-mono text-slate-500 flex items-center justify-between shrink-0">
        <span>mTLS 1.3 Outbound Stream</span>
        <span className="text-emerald-400">fsnotify active</span>
      </div>

    </div>
  );
}
