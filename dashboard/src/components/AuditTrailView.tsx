import React, { useState, useEffect } from 'react';
import { Eye, Search, Lock, Unlock, ShieldCheck, Download, UserCheck } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { AuditLogger } from '../services/auditLogger';

interface AuditTrailViewProps {
  onClose?: () => void;
}

export const AuditTrailView: React.FC<AuditTrailViewProps> = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    setLogs(AuditLogger.getLogs());
    const unsub = AuditLogger.subscribe((updated) => setLogs(updated));
    return unsub;
  }, []);

  const filteredLogs = logs.filter(log => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      log.user_name.toLowerCase().includes(q) ||
      log.target_field.toLowerCase().includes(q) ||
      log.reason.toLowerCase().includes(q) ||
      log.entity_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="glass-panel rounded-xl p-6 border border-cyber-border space-y-5">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-amber-400" />
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              ROLE-GATED UNMASKING AUDIT TRAIL
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Every identifier unmasking action is permanently recorded for regulatory compliance & forensic accountability.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 text-xs font-mono-code font-bold border border-amber-500/30">
            {logs.length} AUDIT RECORDS
          </span>
        </div>
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
        <input
          type="text"
          placeholder="Search audit trail by reviewer name, field, reason, or entity ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-[#05070a] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono-code placeholder:text-slate-600"
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase tracking-wider font-mono-code border-y border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Timestamp (UTC)</th>
              <th className="py-2.5 px-3">Reviewer</th>
              <th className="py-2.5 px-3">Target Field</th>
              <th className="py-2.5 px-3">Masked &rarr; Unmasked Value</th>
              <th className="py-2.5 px-3">Regulatory Justification</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono-code text-[11px]">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-8 text-center text-slate-500">
                  No audit logs matching search.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/40 transition">
                  <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <UserCheck className="w-3.5 h-3.5 text-blue-400" />
                      <div>
                        <span className="text-slate-200 font-bold block">{log.user_name}</span>
                        <span className="text-[10px] text-slate-500 font-sans">{log.user_role}</span>
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-amber-300 font-bold">
                    {log.target_field}
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 line-through">{log.masked_value}</span>
                      <span className="text-slate-600">&rarr;</span>
                      <span className="text-emerald-400 font-bold bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-500/30">
                        {log.unmasked_value}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-slate-300 font-sans text-xs">
                    {log.reason}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
};
