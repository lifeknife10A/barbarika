import React, { useState, useEffect } from 'react';
import { 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  Activity, 
  FileText, 
  Terminal, 
  GitBranch, 
  Binary, 
  Search, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Flame, 
  ArrowRight, 
  Eye, 
  EyeOff, 
  Scale, 
  Lock, 
  Radio, 
  Zap, 
  Cpu, 
  Layers, 
  FileCheck, 
  AlertCircle, 
  ExternalLink, 
  ChevronRight, 
  Copy, 
  Check, 
  Download, 
  Crosshair, 
  Wifi, 
  Database, 
  KeyRound, 
  FileSpreadsheet,
  Award,
  Sparkles,
  BarChart3,
  SlidersHorizontal,
  ChevronDown
} from 'lucide-react';

import DualNodeStatus from './DualNodeStatus';
import HashChainVerifier from './HashChainVerifier';
import ProvenanceGraph from './ProvenanceGraph';
import { INITIAL_HASH_CHAIN } from '../data/mockIncidents';

export default function MinimalDashboard({
  currentScenarioKey = "CAT3",
  activeScenario,
  currentStep = 1,
  onStepChange,
  isSlaActive = false,
  primaryNodeState = "HEALTHY",
  watchdogState = "WATCHING",
  heartbeatSeq = 1842,
  tamperViolations = 0,
  events = [],
  selectedEvent,
  onSelectEvent,
  isPiiMasked = true,
  onToggleMask,
  onOpenReport,
  onTamperStatusChange,
  personaMode = "CISO",
  onToggleHost
}) {
  // Main view tab: 'OVERVIEW' | 'COMPLIANCE' | 'VAULT' | 'DAG'
  const [activeTab, setActiveTab] = useState('OVERVIEW');
  
  // Log filtering & search
  const [logFilter, setLogFilter] = useState('ALL');
  const [logSearch, setLogSearch] = useState('');
  const [copiedHash, setCopiedHash] = useState(false);

  const isHostKilled = primaryNodeState === "KILLED";
  const isHostCompromised = primaryNodeState === "COMPROMISED";

  // Filter logs for engineer console
  const filteredEvents = events.filter((ev) => {
    if (logFilter === 'AUTH' && ev.source !== 'auth.log') return false;
    if (logFilter === 'NGINX' && !ev.source.includes('nginx')) return false;
    if (logFilter === 'CRITICAL' && ev.severity !== 'CRITICAL' && ev.severity !== 'ALERT') return false;
    if (logSearch) {
      const term = logSearch.toLowerCase();
      const rawText = (isPiiMasked ? ev.redactedRaw : ev.raw) || '';
      return (
        rawText.toLowerCase().includes(term) ||
        String(ev.id).includes(term) ||
        ev.source.toLowerCase().includes(term) ||
        ev.facility.toLowerCase().includes(term)
      );
    }
    return true;
  });

  const handleCopyHash = (text) => {
    navigator.clipboard?.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1500);
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-2.5 overflow-hidden text-slate-200">
      
      {/* ========================================================================= */}
      {/* 1. CYBEROPTIK BENCHMARK 1: CROWDSTRIKE FALCON COMMAND COCKPIT              */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2.5 shrink-0">
        
        {/* CARD 1: CROWDSTRIKE-STYLE STATUTORY 6H SLA CLOCK */}
        <div className={`rounded-xl border p-3.5 relative overflow-hidden transition-all shadow-lg ${
          isSlaActive 
            ? 'bg-gradient-to-br from-rose-950/50 via-[#0a0f1e] to-[#040711] border-rose-500/60 shadow-[0_0_20px_rgba(225,29,72,0.2)]' 
            : 'bg-[#070b16]/95 border-slate-800'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md ${isSlaActive ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-slate-800 text-slate-400'}`}>
                <Clock className={`w-4 h-4 ${isSlaActive ? 'animate-pulse' : ''}`} />
              </div>
              <span className="text-[11px] font-mono font-bold tracking-wider uppercase text-slate-200">
                Statutory 6H SLA
              </span>
            </div>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 font-semibold">
              IT Act Sec 70B(6)
            </span>
          </div>

          <div className="flex items-baseline justify-between mt-1">
            <div className={`text-2xl font-black font-mono tracking-tight ${isSlaActive ? 'text-rose-400' : 'text-slate-100'}`}>
              {isSlaActive ? '05:58:32' : '06:00:00'}
            </div>
            <span className={`text-[10px] font-mono font-bold ${isSlaActive ? 'text-rose-400 animate-pulse' : 'text-slate-400'}`}>
              {isSlaActive ? 'COUNTDOWN ACTIVE' : 'STANDBY'}
            </span>
          </div>

          {/* CrowdStrike Accent Progress Line */}
          <div className="w-full bg-slate-800/80 rounded-full h-1.5 mt-2.5 overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-1000 ${
                isSlaActive ? 'w-[98%] bg-gradient-to-r from-rose-600 via-rose-500 to-amber-500 shadow-[0_0_10px_#f43f5e]' : 'w-full bg-slate-700'
              }`}
            />
          </div>
          <div className="flex justify-between items-center text-[9px] font-mono text-slate-400 mt-1.5">
            <span>Breach T0: 10:14:05 UTC</span>
            <span className="text-rose-400 font-semibold">Section 70B Mandate</span>
          </div>
        </div>

        {/* CARD 2: DATADOG-STYLE REAL-TIME TELEMETRY STREAM & SPARKLINE */}
        <div className={`rounded-xl border p-3.5 relative overflow-hidden transition-all shadow-lg ${
          isHostKilled 
            ? 'bg-gradient-to-br from-rose-950/40 via-[#0a0f1e] to-[#040711] border-rose-500/50' 
            : 'bg-[#070b16]/95 border-slate-800'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md ${isHostKilled ? 'bg-rose-500/20 text-rose-400' : 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'}`}>
                <Radio className={`w-4 h-4 ${!isHostKilled ? 'animate-pulse' : ''}`} />
              </div>
              <span className="text-[11px] font-mono font-bold tracking-wider uppercase text-slate-200">
                mTLS Telemetry Ingest
              </span>
            </div>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
              primary-srv-01
            </span>
          </div>

          <div className="flex items-baseline justify-between mt-1">
            <div className="text-2xl font-black font-mono tracking-tight text-white flex items-center gap-1.5">
              {isHostKilled ? (
                <span className="text-rose-400">0.0 EPS (HALTED)</span>
              ) : (
                <>
                  <span className="text-cyan-300">34.2</span>
                  <span className="text-xs text-slate-400 font-normal">EPS • Ed25519</span>
                </>
              )}
            </div>
            <span className={`text-[10px] font-mono font-bold ${isHostKilled ? 'text-rose-400' : 'text-emerald-400'}`}>
              {isHostKilled ? 'DAEMON KILLED' : '0 INBOUND PORTS'}
            </span>
          </div>

          {/* Datadog Ingestion Velocity Sparkline */}
          <div className="mt-2 h-4 w-full flex items-end gap-1">
            {[40, 65, 55, 80, 95, 70, 85, 90, 60, 75, 88, 92, 100, 85, 90].map((val, idx) => (
              <div 
                key={idx}
                style={{ height: isHostKilled ? '15%' : `${val}%` }}
                className={`flex-1 rounded-xs transition-all ${
                  isHostKilled 
                    ? 'bg-rose-900/40' 
                    : idx > 10 
                    ? 'bg-cyan-400 shadow-[0_0_6px_#22d3ee]' 
                    : 'bg-cyan-600/60'
                }`}
              />
            ))}
          </div>

          <div className="flex justify-between items-center text-[9px] font-mono text-slate-400 mt-1">
            <span>Daemon RAM: &lt;15MB</span>
            <span>One-Way TLS 1.3</span>
          </div>
        </div>

        {/* CARD 3: ARCHITECTURE INVERTED WATCHDOG (DEAD-MAN'S SWITCH) */}
        <div className={`rounded-xl border p-3.5 relative overflow-hidden transition-all shadow-lg ${
          isHostKilled 
            ? 'bg-gradient-to-br from-rose-950/50 via-[#0a0f1e] to-[#040711] border-rose-500/60 shadow-[0_0_20px_rgba(225,29,72,0.2)]' 
            : 'bg-[#070b16]/95 border-slate-800'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md ${isHostKilled ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'}`}>
                <Zap className="w-4 h-4" />
              </div>
              <span className="text-[11px] font-mono font-bold tracking-wider uppercase text-slate-200">
                Inverted Watchdog
              </span>
            </div>
            <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
              isHostKilled ? 'bg-rose-950 text-rose-300 border-rose-800' : 'bg-amber-950 text-amber-300 border-amber-800'
            }`}>
              {isHostKilled ? 'DEAD-MAN TRIPPED' : '5s SLIDING WINDOW'}
            </span>
          </div>

          <div className="flex items-baseline justify-between mt-1">
            <div className={`text-2xl font-black font-mono tracking-tight ${isHostKilled ? 'text-rose-400' : 'text-amber-300'}`}>
              {isHostKilled ? '3/3 MISSED' : '0/3 MISSED'}
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Seq #{heartbeatSeq}
            </span>
          </div>

          {/* 3-Window Sliding Heartbeat Monitor */}
          <div className="grid grid-cols-3 gap-1.5 mt-2.5 h-1.5">
            <div className={`rounded-full ${isHostKilled ? 'bg-rose-500' : 'bg-emerald-400'}`} />
            <div className={`rounded-full ${isHostKilled ? 'bg-rose-500' : 'bg-emerald-400'}`} />
            <div className={`rounded-full ${isHostKilled ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'}`} />
          </div>
          <div className="flex justify-between items-center text-[9px] font-mono text-slate-400 mt-1.5">
            <span>Threshold: 15s Silence</span>
            <span>Vault Status: {isHostKilled ? 'LOCKED READ-ONLY' : 'ARMED'}</span>
          </div>

          {onToggleHost && (
            <button
              onClick={onToggleHost}
              className={`mt-2 w-full py-1 px-2 rounded font-mono text-[10px] font-bold border transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                isHostKilled 
                  ? 'bg-emerald-950/60 hover:bg-emerald-900/60 border-emerald-500/50 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.2)]' 
                  : 'bg-rose-950/40 hover:bg-rose-900/40 border-rose-500/40 text-rose-300'
              }`}
            >
              <Zap className="w-3 h-3" />
              <span>{isHostKilled ? '✓ Revive Host Daemon' : '⚡ Simulate kill -9 Wipe'}</span>
            </button>
          )}
        </div>

        {/* CARD 4: VANTA-STYLE AUTOMATED COMPLIANCE & AUDIT SCORE */}
        <div className={`rounded-xl border p-3.5 relative overflow-hidden transition-all shadow-lg ${
          tamperViolations > 0 
            ? 'bg-gradient-to-br from-rose-950/50 via-[#0a0f1e] to-[#040711] border-rose-500/60' 
            : 'bg-[#070b16]/95 border-slate-800'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md ${tamperViolations > 0 ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'}`}>
                {tamperViolations > 0 ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
              </div>
              <span className="text-[11px] font-mono font-bold tracking-wider uppercase text-slate-200">
                Audit Readiness (Vanta-Tier)
              </span>
            </div>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-semibold">
              Sec 65B Certified
            </span>
          </div>

          <div className="flex items-baseline justify-between mt-1">
            <div className={`text-2xl font-black font-mono tracking-tight ${tamperViolations > 0 ? 'text-rose-400' : 'text-emerald-300'}`}>
              {tamperViolations > 0 ? 'CORRUPTED' : '100% READY'}
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              27/27 Fields Verified
            </span>
          </div>

          {/* Vanta Progress Indicator */}
          <div className="w-full bg-slate-800/80 rounded-full h-1.5 mt-2.5 overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-700 ${
                tamperViolations > 0 ? 'w-full bg-rose-500' : 'w-full bg-emerald-400 shadow-[0_0_10px_#34d399]'
              }`}
            />
          </div>
          <div className="flex justify-between items-center text-[9px] font-mono text-slate-400 mt-1.5">
            <span>Annexure I Auto-Sealed</span>
            <span className="text-emerald-400 font-bold">SHA-256 Validated</span>
          </div>
        </div>

      </div>

      {/* ========================================================================= */}
      {/* 2. CYBEROPTIK BENCHMARK 2: SENTINELONE STORYLINE™ ATTACK RECONSTRUCTION   */}
      {/* ========================================================================= */}
      <div className="rounded-xl border border-slate-800 bg-[#070b16]/95 px-3.5 py-2.5 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 shrink-0 shadow-md">
        
        <div className="flex items-center gap-2 text-slate-300 shrink-0 font-mono text-xs">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse shadow-[0_0_8px_#f43f5e]" />
          <span className="font-bold uppercase tracking-wider text-slate-200">Storyline™ Attack Path:</span>
          <span className="text-[11px] text-slate-400 font-sans hidden lg:inline">
            (SentinelOne-Style Deterministic Sequence)
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 flex-1 font-mono text-xs">
          {[
            { step: 1, title: '01. Ingestion', sub: 'mTLS Stream Active' },
            { step: 2, title: '02. Intrusion', sub: `${activeScenario?.ruleId || 'SIGMA CAT-III'}` },
            { step: 3, title: '03. Daemon Kill', sub: 'kill -9 Host Wipe' },
            { step: 4, title: '04. Vault Audit', sub: 'SHA-256 Proof (38ms)' },
            { step: 5, title: '05. Annexure I', sub: 'Dispatch Ready' }
          ].map((s) => {
            const isCurrent = currentStep === s.step;
            const isPast = currentStep > s.step;
            return (
              <button
                key={s.step}
                onClick={() => onStepChange && onStepChange(s.step)}
                className={`p-2 rounded-lg border text-left transition-all cursor-pointer relative overflow-hidden ${
                  isCurrent
                    ? 'bg-rose-950/40 border-rose-500/70 shadow-[0_0_15px_rgba(225,29,72,0.25)] text-white font-bold ring-1 ring-rose-500/50'
                    : isPast
                    ? 'bg-[#0a0f1d] border-slate-800 text-slate-300 hover:border-slate-700'
                    : 'bg-[#050811] border-slate-900 text-slate-500 hover:text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] mb-0.5">
                  <span className="font-bold">{s.title}</span>
                  {isPast ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  ) : isCurrent ? (
                    <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping" />
                  ) : null}
                </div>
                <div className="text-[10px] text-slate-400 truncate">
                  {s.sub}
                </div>
              </button>
            );
          })}
        </div>

      </div>

      {/* ========================================================================= */}
      {/* 3. DUAL-PANE MISSION CONTROL WORKSPACE                                    */}
      {/* ========================================================================= */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
        
        {/* ------------------------------------------------------------------------- */}
        {/* LEFT COLUMN (5 Cols): PERSONA COCKPIT & DUAL-NODE TOPOLOGY                */}
        {/* ------------------------------------------------------------------------- */}
        <div className="lg:col-span-5 flex flex-col gap-2.5 min-h-0 overflow-y-auto pr-0.5">
          
          {/* Executive & Regulatory Briefing Card */}
          <div className="rounded-xl border border-slate-800 bg-[#070b16]/95 p-4 flex flex-col justify-between shadow-lg relative overflow-hidden">
            <div>
              {/* Header with Live Status Pill */}
              <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                    {personaMode === 'CISO' ? 'CISO Executive Briefing' : 'SecOps Incident Telemetry'}
                  </h3>
                </div>
                <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full border uppercase font-bold bg-rose-950/60 text-rose-300 border-rose-500/40">
                  {currentStep === 1 ? 'NOMINAL' : currentStep === 2 ? 'ATTACK DETECTED' : currentStep === 3 ? 'DAEMON TERMINATED' : currentStep === 4 ? 'AUDIT VERIFIED' : 'READY TO FILE'}
                </span>
              </div>

              {/* Persona Specific Details */}
              {personaMode === 'CISO' ? (
                <div className="mb-3 p-3 rounded-lg bg-rose-950/25 border border-rose-900/50 text-xs font-sans">
                  <div className="flex items-center justify-between text-rose-300 font-bold mb-1.5 font-mono text-[10px]">
                    <span className="flex items-center gap-1.5">
                      <Scale className="w-3.5 h-3.5 text-rose-400" />
                      STATUTORY LIABILITY SHIELD (IT ACT SEC 70B):
                    </span>
                    <span className="text-emerald-400 font-bold">₹1 CRORE PENALTY MITIGATED</span>
                  </div>
                  <p className="text-slate-300 text-xs leading-relaxed">
                    Under CERT-In Directions 2022 (Para 5(i)), failure to report within 6 hours triggers Section 70B(7) criminal penal sanctions (up to 1 year imprisonment and heavy fines). Barbarika automatically populates all 27 Annexure I fields to ensure statutory immunity.
                  </p>
                </div>
              ) : (
                <div className="mb-3 p-3 rounded-lg bg-cyan-950/20 border border-cyan-900/40 text-xs font-mono">
                  <div className="flex items-center justify-between text-cyan-300 font-bold mb-1.5 text-[10px]">
                    <span className="flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                      DAEMON SOCKET TELEMETRY &amp; MITRE MATRIX:
                    </span>
                    <span className="text-emerald-400">Ed25519 VALID</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
                    <div><span className="text-slate-500 block text-[9px]">DAEMON:</span> Go &lt;15MB RAM</div>
                    <div><span className="text-slate-500 block text-[9px]">INGRESS:</span> 0 Open (mTLS Egress)</div>
                    <div><span className="text-slate-500 block text-[9px]">SIGMA RULE:</span> <span className="text-sky-300">{activeScenario?.ruleId || 'SIGMA-CAT3-001'}</span></div>
                    <div><span className="text-slate-500 block text-[9px]">MITRE TACTIC:</span> <span className="text-rose-400">{activeScenario?.mitreTechniques?.[0] || 'T1190'}</span></div>
                  </div>
                </div>
              )}

              {/* Dynamic Step Narrative */}
              <h4 className="text-sm font-bold font-sans text-white mb-2 leading-snug">
                {currentStep === 1 && "System Nominal • Continuous Ingestion Active"}
                {currentStep === 2 && "Adversary Intrusion Detected • 6H Statutory Clock Started"}
                {currentStep === 3 && "Attacker Wiped Host • Inverted Watchdog Dead-Man Switch Fired"}
                {currentStep === 4 && "Cryptographic Audit Executed • Evidence 100% Intact"}
                {currentStep === 5 && "Statutory CERT-In Annexure I Ready for Official Filing"}
              </h4>

              <p className="text-xs text-slate-300 font-sans leading-relaxed">
                {currentStep === 1 && "The lightweight Go agent (<15MB RAM) is running on the production host with zero open inbound listening ports, streaming signed log lines to the isolated Sentry vault over mTLS 1.3."}
                {currentStep === 2 && `An external adversary triggered deterministic Sigma rule ${activeScenario?.ruleId || 'SIGMA-CAT3-001'}. Incident categorized under CERT-In Category ${activeScenario?.category || 'III'} (${activeScenario?.categoryTitle || 'Unauthorized Access'}). Statutory 6-hour Section 70B countdown is ticking.`}
                {currentStep === 3 && "The adversary acquired root privileges and executed kill -9 on the host telemetry agent to eliminate trace evidence. Sentry's inverted watchdog detected 3 consecutive missed heartbeats (15s sliding window) and locked the vault in read-only forensic mode."}
                {currentStep === 4 && "SHA-256 recursive cryptographic hash chain audit executed across all SQLite WAL segments. All 47 records validated against the Genesis Anchor in 38ms with 0 tampering detected, proving complete evidentiary survival."}
                {currentStep === 5 && "All statutory fields for CERT-In Annexure I have been automatically pre-filled from cryptographically verified records. Presidio PII redaction applied. Ready for legal officer attestation and dispatch."}
              </p>
            </div>

            {/* Directive & Annexure-I CTA Button */}
            <div className="mt-4 pt-3.5 border-t border-slate-800/80 space-y-2.5">
              <div className="p-2.5 rounded-lg bg-[#050811] border border-slate-800/80 text-[11px] text-slate-300 font-sans">
                <span className="text-rose-400 font-semibold block mb-0.5 font-mono text-[10px] uppercase">
                  {personaMode === 'CISO' ? 'Executive Action Required:' : 'SecOps Operational Directive:'}
                </span>
                {currentStep === 5 
                  ? "Annexure I statutory packet ready for human-in-the-loop review. Click below to inspect."
                  : "All incident telemetry is sealed with SHA-256 append-only hash chaining in the isolated Sentry enclave."
                }
              </div>

              <button
                onClick={onOpenReport}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-rose-600 via-rose-700 to-rose-800 hover:from-rose-500 hover:to-rose-600 text-white font-sans font-bold text-xs transition-all shadow-md cursor-pointer border border-rose-500/40"
              >
                <FileText className="w-4 h-4" />
                <span>Open Pre-Populated CERT-In Annexure I Form</span>
              </button>
            </div>
          </div>

          {/* Dual-Node Topology Enclave Card */}
          <DualNodeStatus
            primaryState={primaryNodeState}
            watchdogState={watchdogState}
            heartbeatCount={heartbeatSeq}
            recordsIndexed={47}
            tamperCount={tamperViolations}
          />

        </div>

        {/* ------------------------------------------------------------------------- */}
        {/* RIGHT COLUMN (7 Cols): CYBEROPTIK MULTI-TAB WORKSPACE                     */}
        {/* ------------------------------------------------------------------------- */}
        <div className="lg:col-span-7 flex flex-col min-h-0 rounded-xl border border-slate-800 bg-[#070b16]/95 overflow-hidden shadow-lg">
          
          {/* Console Navigation Bar */}
          <div className="p-2.5 border-b border-slate-800 bg-[#060a14] flex flex-wrap items-center justify-between gap-2 shrink-0">
            
            <div className="flex items-center gap-1 font-mono text-xs">
              <button
                onClick={() => setActiveTab('OVERVIEW')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'OVERVIEW'
                    ? 'bg-rose-500/15 text-rose-300 font-bold border border-rose-500/40 shadow-inner'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Terminal className="w-3.5 h-3.5 text-rose-400" />
                <span>Live Telemetry</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                  {events.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('COMPLIANCE')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'COMPLIANCE'
                    ? 'bg-emerald-500/15 text-emerald-300 font-bold border border-emerald-500/40 shadow-inner'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Award className="w-3.5 h-3.5 text-emerald-400" />
                <span>Compliance Hub</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">
                  27/27
                </span>
              </button>

              <button
                onClick={() => setActiveTab('VAULT')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'VAULT'
                    ? 'bg-cyan-500/15 text-cyan-300 font-bold border border-cyan-500/40 shadow-inner'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Binary className="w-3.5 h-3.5 text-cyan-400" />
                <span>Cryptographic Vault</span>
              </button>

              <button
                onClick={() => setActiveTab('DAG')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'DAG'
                    ? 'bg-purple-500/15 text-purple-300 font-bold border border-purple-500/40 shadow-inner'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5 text-purple-400" />
                <span>Attack DAG</span>
              </button>
            </div>

            {/* Presidio Redaction Switch */}
            <button
              onClick={onToggleMask}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono border transition-colors cursor-pointer ${
                isPiiMasked 
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                  : 'bg-amber-950/40 border-amber-500/40 text-amber-300'
              }`}
              title="Presidio PII Redaction Engine"
            >
              {isPiiMasked ? <EyeOff className="w-3 h-3 text-emerald-400" /> : <Eye className="w-3 h-3 text-amber-400" />}
              <span className="text-[11px]">{isPiiMasked ? 'Presidio Redacted' : 'Raw Telemetry'}</span>
            </button>

          </div>

          {/* TAB 1: LIVE TELEMETRY LOGS & EVENT INSPECTOR */}
          {activeTab === 'OVERVIEW' && (
            <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
              
              {/* Search & Filter Toolbar */}
              <div className="px-3 py-2 border-b border-slate-800/80 bg-[#050912] flex items-center justify-between gap-3 shrink-0">
                <div className="flex items-center gap-1 font-mono text-[10px]">
                  {['ALL', 'AUTH', 'NGINX', 'CRITICAL'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setLogFilter(tab)}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        logFilter === tab
                          ? 'bg-rose-600 text-white font-bold shadow-xs'
                          : 'text-slate-400 hover:text-white bg-slate-900/60'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-1.5 bg-[#040711] px-2.5 py-1 rounded-md border border-slate-800 w-44 sm:w-60">
                  <Search className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  <input
                    type="text"
                    placeholder="Search logs, IPs, hashes..."
                    value={logSearch}
                    onChange={(e) => setLogSearch(e.target.value)}
                    className="w-full text-[10px] font-mono bg-transparent border-none text-slate-200 placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>

              {/* Event Stream Split: Table Top, Inspector Bottom */}
              <div className="flex-1 min-h-0 flex flex-col overflow-hidden divide-y divide-slate-800/80">
                
                {/* Table: Log lines */}
                <div className="flex-1 overflow-y-auto divide-y divide-slate-800/50 font-mono text-xs">
                  {filteredEvents.map((ev) => {
                    const isSelected = selectedEvent?.id === ev.id;
                    return (
                      <div
                        key={ev.id}
                        onClick={() => onSelectEvent(ev)}
                        className={`p-2.5 transition-colors cursor-pointer hover:bg-slate-800/40 flex items-start gap-2.5 ${
                          isSelected ? 'bg-rose-950/25 border-l-2 border-rose-500' : ''
                        } ${ev.severity === 'CRITICAL' ? 'bg-rose-950/10' : ''}`}
                      >
                        <div className="w-14 shrink-0 text-[10px] text-slate-400">
                          <span className="text-slate-500 block">#{ev.id}</span>
                          <span className="text-slate-300">{ev.time}</span>
                        </div>

                        <div className="shrink-0">
                          <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase border ${
                            ev.severity === 'CRITICAL'
                              ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                              : ev.severity === 'ALERT'
                              ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                              : 'bg-slate-900 text-slate-400 border-slate-800'
                          }`}>
                            {ev.severity}
                          </span>
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 text-[10px] text-slate-400 mb-0.5">
                            <span className="text-cyan-400">{ev.facility}</span>
                            <span>•</span>
                            <span className="truncate">{ev.source}</span>
                          </div>
                          <div className="text-[11px] text-slate-200 truncate font-mono">
                            {isPiiMasked ? ev.redactedRaw : ev.raw}
                          </div>
                        </div>

                        <div className="hidden sm:block shrink-0 text-[10px] font-mono text-slate-500 truncate w-20 text-right">
                          {ev.hash?.slice(0, 8)}...
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Bottom Inspector Box */}
                {selectedEvent && (
                  <div className="h-44 shrink-0 bg-[#050912] p-3 overflow-y-auto font-mono text-xs flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between pb-1.5 border-b border-slate-800 mb-2">
                        <div className="flex items-center gap-2 text-[11px]">
                          <Activity className="w-3.5 h-3.5 text-cyan-400" />
                          <span className="font-bold text-white">Event #{selectedEvent.id} Inspector</span>
                          <span className="text-slate-500">•</span>
                          <span className="text-slate-400">{selectedEvent.time}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleCopyHash(selectedEvent.hash)}
                            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-white px-2 py-0.5 rounded bg-slate-900 border border-slate-800 cursor-pointer"
                          >
                            {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedHash ? 'Copied' : 'Copy Hash'}</span>
                          </button>
                        </div>
                      </div>

                      <div className="p-2 rounded bg-[#03060d] border border-slate-800 text-[11px] text-slate-300 break-all leading-relaxed mb-2 font-mono">
                        {isPiiMasked ? selectedEvent.redactedRaw : selectedEvent.raw}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1.5 border-t border-slate-800/80">
                      <div className="truncate pr-2">
                        <span className="text-slate-500 mr-1">SHA-256:</span>
                        <span className="text-slate-300">{selectedEvent.hash}</span>
                      </div>
                      <span className="shrink-0 text-emerald-400 font-bold">Ed25519 Verified</span>
                    </div>
                  </div>
                )}

              </div>

            </div>
          )}

          {/* TAB 2: CYBEROPTIK BENCHMARK 3: VANTA-STYLE COMPLIANCE HUB */}
          {activeTab === 'COMPLIANCE' && (
            <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4 font-sans">
              
              {/* Compliance Score Ribbon */}
              <div className="rounded-xl border border-emerald-500/30 bg-gradient-to-r from-emerald-950/30 via-[#070e1a] to-emerald-950/30 p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full border-2 border-emerald-500/40 bg-emerald-500/10 flex items-center justify-center font-mono font-bold text-emerald-400 text-lg shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                    100%
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
                      CERT-In Statutory Compliance Verified
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    </h3>
                    <p className="text-xs text-slate-400">
                      All 27 required Annexure I fields cryptographically anchored in SQLite WAL
                    </p>
                  </div>
                </div>

                <button
                  onClick={onOpenReport}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs font-mono shadow-md cursor-pointer transition-all shrink-0"
                >
                  Generate Official CERT-In Packet
                </button>
              </div>

              {/* Statutory Trust Badges Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                
                <div className="p-3 rounded-lg border border-slate-800 bg-[#050912]">
                  <div className="flex items-center justify-between mb-1 text-slate-200 font-bold">
                    <span className="flex items-center gap-1.5">
                      <Scale className="w-3.5 h-3.5 text-amber-400" />
                      IT Act 2000 Section 70B
                    </span>
                    <span className="text-[10px] text-emerald-400">ENFORCED</span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                    6-hour notification mandate met. Shields organization from Section 70B(7) criminal penal exposure and fines up to ₹1 Crore.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-800 bg-[#050912]">
                  <div className="flex items-center justify-between mb-1 text-slate-200 font-bold">
                    <span className="flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      Indian Evidence Act Sec 65B
                    </span>
                    <span className="text-[10px] text-emerald-400">COURT ADMISSIBLE</span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                    Recursive SHA-256 hash chaining guarantees electronic record admissibility without risk of third-party tampering.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-800 bg-[#050912]">
                  <div className="flex items-center justify-between mb-1 text-slate-200 font-bold">
                    <span className="flex items-center gap-1.5">
                      <KeyRound className="w-3.5 h-3.5 text-purple-400" />
                      Ed25519 Payload Signing
                    </span>
                    <span className="text-[10px] text-emerald-400">VALIDATED</span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                    Every syslog line is signed at generation on the primary host using local asymmetric keys before transmission.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-800 bg-[#050912]">
                  <div className="flex items-center justify-between mb-1 text-slate-200 font-bold">
                    <span className="flex items-center gap-1.5">
                      <EyeOff className="w-3.5 h-3.5 text-rose-400" />
                      Presidio PII Protection
                    </span>
                    <span className="text-[10px] text-emerald-400">ACTIVE</span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                    Automated entity detection masks Aadhaar, PAN, and employee IPs prior to external dispatch to CERT-In.
                  </p>
                </div>

              </div>

            </div>
          )}

          {/* TAB 3: CRYPTOGRAPHIC HASH CHAIN AUDIT */}
          {activeTab === 'VAULT' && (
            <div className="flex-1 min-h-0 overflow-y-auto p-3">
              <HashChainVerifier
                records={INITIAL_HASH_CHAIN}
                onTamperStatusChange={onTamperStatusChange}
              />
            </div>
          )}

          {/* TAB 4: ATTACK PROVENANCE DAG */}
          {activeTab === 'DAG' && (
            <div className="flex-1 min-h-0 overflow-y-auto p-3 flex flex-col justify-between">
              <ProvenanceGraph scenarioData={activeScenario} />
              
              <div className="mt-3 p-3 rounded-lg bg-[#050912] border border-slate-800 font-mono text-xs">
                <div className="flex items-center justify-between mb-1 text-cyan-300 font-bold text-[11px]">
                  <span>Deterministic Sigma Correlation Pipeline</span>
                  <span className="text-emerald-400">Zero LLM Hallucination</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans leading-relaxed">
                  Sigma rules match exact kernel events and syslog patterns deterministically. No probabilistic LLM inference is used for threat detection, guaranteeing complete evidentiary integrity under Indian Evidence Act Section 65B.
                </p>
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
