import React from 'react';
import { 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  Activity, 
  AlertTriangle,
  Lock,
  Zap,
  CheckCircle2
} from 'lucide-react';

export default function DashboardMetrics({
  isSlaActive = false,
  scenarioData,
  primaryState = "HEALTHY",
  watchdogState = "WATCHING",
  tamperCount = 0,
  recordsCount = 47,
  heartbeatSeq = 1842
}) {
  const isPrimaryKilled = primaryState === "KILLED";

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 shrink-0">
      
      {/* 1. Mandatory 6-Hour SLA Window */}
      <div className={`p-2 rounded-lg border transition-colors ${
        isSlaActive 
          ? 'bg-amber-950/20 border-amber-800/60' 
          : 'bg-[#090d16] border-slate-800/80'
      }`}>
        <div className="flex items-center justify-between text-[10px] font-mono mb-1">
          <span className="text-slate-400 uppercase flex items-center gap-1">
            <Clock className="w-3 h-3 text-amber-400" />
            Statutory SLA Window
          </span>
          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
            isSlaActive ? 'bg-amber-900/60 text-amber-300' : 'bg-slate-800 text-slate-400'
          }`}>
            {isSlaActive ? 'ACTIVE 6H' : 'STANDBY'}
          </span>
        </div>
        <div className="flex items-baseline justify-between">
          <span className={`text-base font-bold font-mono ${
            isSlaActive ? 'text-amber-400' : 'text-slate-300'
          }`}>
            {isSlaActive ? '05:58:32' : '06:00:00'}
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            IT Act Sec 70B(6)
          </span>
        </div>
        <div className="text-[10px] text-slate-400 truncate mt-0.5 font-sans">
          {scenarioData?.category || 'Category III'}: 6h mandatory deadline
        </div>
      </div>

      {/* 2. Active Threat Severity & Sigma Rule */}
      <div className={`p-2 rounded-lg border transition-colors ${
        scenarioData?.severity === 'CRITICAL'
          ? 'bg-rose-950/20 border-rose-900/60'
          : 'bg-[#090d16] border-slate-800/80'
      }`}>
        <div className="flex items-center justify-between text-[10px] font-mono mb-1">
          <span className="text-slate-400 uppercase flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            Threat Correlation
          </span>
          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-rose-950 text-rose-300 border border-rose-800/60">
            {scenarioData?.severity || 'CRITICAL'}
          </span>
        </div>
        <div className="flex items-baseline justify-between">
          <span className="text-base font-bold font-mono text-white truncate">
            {scenarioData?.ruleId || 'SIGMA-001'}
          </span>
          <span className="text-[10px] text-rose-400 font-mono">
            CVSS 9.8
          </span>
        </div>
        <div className="text-[10px] text-slate-400 truncate mt-0.5 font-sans">
          {scenarioData?.ruleName || 'High-frequency brute force detection'}
        </div>
      </div>

      {/* 3. Cryptographic Chain Integrity */}
      <div className={`p-2 rounded-lg border transition-colors ${
        tamperCount > 0 
          ? 'bg-rose-950/20 border-rose-900/60' 
          : 'bg-[#090d16] border-slate-800/80'
      }`}>
        <div className="flex items-center justify-between text-[10px] font-mono mb-1">
          <span className="text-slate-400 uppercase flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            Evidence Cryptography
          </span>
          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
            tamperCount > 0 
              ? 'bg-rose-950 text-rose-300' 
              : 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
          }`}>
            {tamperCount > 0 ? 'TAMPER ALERT' : '100% INTACT'}
          </span>
        </div>
        <div className="flex items-baseline justify-between">
          <span className={`text-base font-bold font-mono ${
            tamperCount > 0 ? 'text-rose-400' : 'text-emerald-400'
          }`}>
            {tamperCount > 0 ? 'CHAIN BROKEN' : `${recordsCount} Blocks SHA-256`}
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            42ms Audit
          </span>
        </div>
        <div className="text-[10px] text-slate-400 truncate mt-0.5 font-sans">
          RFC 6962 append-only ledger • Zero tampering
        </div>
      </div>

      {/* 4. Dual Trust-Domain Infrastructure Health */}
      <div className={`p-2 rounded-lg border transition-colors ${
        isPrimaryKilled 
          ? 'bg-rose-950/20 border-rose-900/60' 
          : 'bg-[#090d16] border-slate-800/80'
      }`}>
        <div className="flex items-center justify-between text-[10px] font-mono mb-1">
          <span className="text-slate-400 uppercase flex items-center gap-1">
            <Server className="w-3 h-3 text-sky-400" />
            Dual Topology Nodes
          </span>
          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
            isPrimaryKilled 
              ? 'bg-rose-950 text-rose-300' 
              : 'bg-sky-950 text-sky-300 border border-sky-800/60'
          }`}>
            {isPrimaryKilled ? 'DEAD-MAN SWITCH' : 'mTLS 1.3 ACTIVE'}
          </span>
        </div>
        <div className="flex items-baseline justify-between">
          <span className="text-base font-bold font-mono text-slate-200">
            {isPrimaryKilled ? 'Host Flatlined' : '2 / 2 Online'}
          </span>
          <span className="text-[10px] text-sky-400 font-mono">
            &lt;15MB RAM
          </span>
        </div>
        <div className="text-[10px] text-slate-400 truncate mt-0.5 font-sans">
          {isPrimaryKilled ? 'Sentry locked in read-only forensic mode' : '0 Inbound ports • 5s sliding watchdog'}
        </div>
      </div>

    </div>
  );
}
