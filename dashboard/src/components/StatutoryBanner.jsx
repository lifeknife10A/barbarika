import React from 'react';
import { AlertTriangle, Scale, ShieldAlert, FileWarning } from 'lucide-react';

export default function StatutoryBanner({ isSlaActive, category = "Category III" }) {
  return (
    <aside 
      aria-label="Statutory Notice" 
      className={`w-full px-3.5 py-1.5 border-b text-[11px] font-mono transition-colors flex items-center justify-between gap-3 shrink-0 ${
        isSlaActive 
          ? 'bg-rose-50 border-rose-200 text-rose-800' 
          : 'bg-slate-100/90 border-slate-200 text-slate-700'
      }`}
    >
      {/* Left Statutory Directive Notification */}
      <div className="flex items-center gap-2.5 truncate">
        <span className="flex h-2 w-2 relative shrink-0">
          {isSlaActive ? (
            <>
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500" />
            </>
          ) : (
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          )}
        </span>
        <span className="font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1 shrink-0">
          {isSlaActive ? <AlertTriangle className="w-3.5 h-3.5 text-rose-600" /> : <ShieldAlert className="w-3.5 h-3.5 text-emerald-600" />}
          CERT-IN STATUTORY MANDATE:
        </span>
        <span className="truncate text-slate-600">
          MeitY Cyber Security Directions (No. 20(3)/2022-CERT-In) • Section 70B(6) IT Act 2000
        </span>
      </div>

      {/* Center & Right Penal & Deadline Clause */}
      <div className="hidden md:flex items-center gap-3 shrink-0 text-[10px]">
        <div className="flex items-center gap-1 text-slate-600">
          <Scale className="w-3 h-3 text-amber-600" />
          <span>Statutory Penalty: IT Act Sec 70B(7) Liability (Up to ₹1 Crore)</span>
        </div>

        <div className="h-3 w-[1px] bg-slate-300" />

        <div className="flex items-center gap-1.5 font-bold">
          <span className="text-slate-500">Reporting Window:</span>
          <span className={`px-2 py-0.5 rounded font-mono ${
            isSlaActive 
              ? 'bg-rose-100 text-rose-800 border border-rose-200 animate-pulse' 
              : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
          }`}>
            {isSlaActive ? `ACTIVE: 6H SLA (${category})` : '6-Hour Mandatory SLA Window'}
          </span>
        </div>
      </div>
    </aside>
  );
}

