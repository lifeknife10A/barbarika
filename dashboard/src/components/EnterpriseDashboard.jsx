import React, { useState } from 'react';
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
  ArrowUpRight,
  Eye, 
  EyeOff, 
  Scale, 
  Lock,
  Radio,
  Zap,
  Check,
  AlertCircle,
  ExternalLink,
  Shield,
  Cpu,
  ChevronRight,
  RotateCcw
} from 'lucide-react';

export default function EnterpriseDashboard({
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
  onToggleHost
}) {
  // Console Tab: 'FEED' | 'VAULT' | 'DAG' | 'INFRA'
  const [activeTab, setActiveTab] = useState('FEED');
  
  // Log filtering
  const [logFilter, setLogFilter] = useState('ALL');
  const [logSearch, setLogSearch] = useState('');

  // Cryptographic audit state
  const [verifying, setVerifying] = useState(false);
  const [auditResult, setAuditResult] = useState({
    status: 'PASS',
    recordsCount: 47,
    elapsedMs: 38,
    details: 'All 47 records cryptographically validated against SHA-256 genesis root. 0 tampering detected.'
  });

  const isHostKilled = primaryNodeState === "KILLED";
  const isHostCompromised = primaryNodeState === "COMPROMISED";
  const isWatchdogTripped = watchdogState === "SUSPECTED_COMPROMISE";

  // Executive narrative for non-programmers, CISO, and hackathon judges
  const getExecutiveNarrative = () => {
    if (isHostKilled) {
      return {
        title: "Adversary Attacked Host • Sentry Dead-Man's Switch Engaged",
        badge: "HOST FLATLINED",
        badgeStyle: "bg-rose-100 text-rose-800 border-rose-200",
        narrative: "The attacker gained root privileges and executed a force-kill (kill -9) on the host monitoring daemon to scrub logs. Sentry's Inverted Watchdog detected 3 consecutive missed pings (15s sliding window silence) and quarantined the host. All 47 evidence records remain completely intact in the isolated vault.",
        action: "Host quarantined. Sentry Vault locked in read-only forensic mode."
      };
    }

    switch (currentStep) {
      case 1:
        return {
          title: "System Nominal • Continuous Outbound Telemetry Active",
          badge: "HEALTHY",
          badgeStyle: "bg-emerald-100 text-emerald-800 border-emerald-200",
          narrative: "The system is operating normally. The lightweight Go daemon (<15MB RAM) is tailing security logs with zero open inbound ports. The isolated Sentry vault is actively monitoring 5-second heartbeats.",
          action: "Routine monitoring active. All evidence chains are intact."
        };
      case 2:
        return {
          title: "Intrusion Attempt Detected • 6-Hour Reporting Clock Active",
          badge: "THREAT DETECTED",
          badgeStyle: "bg-amber-100 text-amber-800 border-amber-200",
          narrative: `An external adversary is attempting high-frequency unauthorized access. Deterministic Sigma correlation matched rule ${activeScenario?.ruleId || 'SIGMA-CAT3-001'}. Classified under ${activeScenario?.category || 'Category III'} (${activeScenario?.categoryTitle || 'Unauthorized Access'}). The mandatory 6-hour Section 70B reporting deadline has started.`,
          action: "Drafting CERT-In Annexure I notice. Telemetry logs sealed in Sentry vault."
        };
      case 3:
        return {
          title: "Adversary Attacked Host • Sentry Dead-Man's Switch Engaged",
          badge: "HOST FLATLINED",
          badgeStyle: "bg-rose-100 text-rose-800 border-rose-200",
          narrative: "The attacker gained root privileges and executed kill -9 on the monitoring agent to eliminate traces. Sentry's Inverted Watchdog detected 3 missed pings (15s silence) and quarantined the host. Evidence in Sentry Vault is 100% intact.",
          action: "Host quarantined. Sentry Vault locked in read-only forensic mode."
        };
      case 4:
        return {
          title: "Cryptographic Audit Verified • Evidence 100% Intact",
          badge: "AUDIT VERIFIED",
          badgeStyle: "bg-blue-100 text-blue-800 border-blue-200",
          narrative: "Cryptographic SHA-256 recursive chain verification completed across all SQLite WAL blocks. Genesis root validated. 47 historical records validated in 38ms with zero tampering detected, proving evidence survived the host wipe.",
          action: "Forensic evidence ready for statutory attestation and legal officer sign-off."
        };
      case 5:
        return {
          title: "Official Annexure I Prepared • Ready for Statutory Submission",
          badge: "COMPLIANCE READY",
          badgeStyle: "bg-emerald-100 text-emerald-800 border-emerald-200",
          narrative: "All 12 statutory fields for CERT-In Annexure I have been automatically pre-populated from deterministic cryptographic logs. Customer PII has been redacted using Presidio. PGP-encrypted .eml dispatch packet is ready for dispatch to incident@cert-in.org.in.",
          action: "Human approval required. Click 'Generate Official Annexure I' to inspect and file."
        };
      default:
        return {
          title: "Telemetry Stream Active",
          badge: "MONITORING",
          badgeStyle: "bg-slate-100 text-slate-700 border-slate-200",
          narrative: "System monitoring active.",
          action: "Standing by."
        };
    }
  };

  const narrative = getExecutiveNarrative();

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

  // 1-Click Cryptographic Audit Handler
  const handleRunAudit = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      if (tamperViolations > 0) {
        setAuditResult({
          status: 'FAIL',
          recordsCount: 47,
          elapsedMs: 38,
          details: 'CRITICAL: Hash mismatch detected in block #5! Cryptographic chain broken.'
        });
      } else {
        setAuditResult({
          status: 'PASS',
          recordsCount: 47,
          elapsedMs: 39,
          details: 'All 47 records verified against SHA-256 genesis anchor. 0 tampering detected.'
        });
      }
    }, 400);
  };

  const handleSimulateTamper = () => {
    if (onTamperStatusChange) {
      const nextCount = tamperViolations > 0 ? 0 : 1;
      onTamperStatusChange(nextCount);
      setTimeout(() => {
        if (nextCount > 0) {
          setAuditResult({
            status: 'FAIL',
            recordsCount: 47,
            elapsedMs: 39,
            details: 'TAMPER DETECTED: 1 bit flipped in block #5 on primary host. Sentry detected chain invalidation.'
          });
        } else {
          setAuditResult({
            status: 'PASS',
            recordsCount: 47,
            elapsedMs: 41,
            details: 'Authentic hash chain restored. All 47 records verified.'
          });
        }
      }, 150);
    }
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-2.5 overflow-hidden text-slate-800">
      
      {/* ========================================================================= */}
      {/* ROW 1: 4 EXECUTIVE ENTERPRISE KPI CARDS (NinjaOne / Vanta Style)           */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5 shrink-0">
        
        {/* CARD 1: 6-HOUR STATUTORY SLA WINDOW (With Circular Donut Gauge) */}
        <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 shadow-xs flex items-center justify-between">
          <div className="flex items-center gap-3">
            {/* SVG Donut Ring (Inspired by Screenshot 1) */}
            <div className="relative w-12 h-12 shrink-0 flex items-center justify-center">
              <svg className="w-12 h-12 transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-100"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={isSlaActive ? "text-amber-500" : "text-emerald-500"}
                  strokeDasharray={isSlaActive ? "96, 100" : "100, 100"}
                  strokeLinecap="round"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <Clock className={`w-4 h-4 ${isSlaActive ? 'text-amber-600 animate-pulse' : 'text-slate-400'}`} />
              </div>
            </div>

            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
                  Statutory 6H SLA
                </span>
                <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-bold ${
                  isSlaActive ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'
                }`}>
                  {isSlaActive ? 'ACTIVE' : 'STANDBY'}
                </span>
              </div>
              <div className={`text-xl font-bold font-mono tracking-tight leading-tight mt-0.5 ${
                isSlaActive ? 'text-amber-700' : 'text-slate-900'
              }`}>
                {isSlaActive ? '05:58:32' : '06:00:00'}
              </div>
              <div className="text-[10px] text-slate-500 font-sans mt-0.5">
                Section 70B(6) IT Act Mandate
              </div>
            </div>
          </div>

          <div className="text-right hidden sm:block">
            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {activeScenario?.category}
            </span>
            <span className="text-[9px] text-slate-400 block mt-1 font-mono">CERT-In SLA</span>
          </div>
        </div>

        {/* CARD 2: HOST RESILIENCE & SENTRY WATCHDOG (FIXES "LOST HOST NOT WORKING") */}
        <div className={`bg-white rounded-xl border p-3.5 shadow-xs flex flex-col justify-between transition-colors ${
          isHostKilled ? 'border-rose-300 bg-rose-50/40' : 'border-slate-200/90'
        }`}>
          <div>
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
              <div className="flex items-center gap-1.5">
                <Server className={`w-3.5 h-3.5 ${isHostKilled ? 'text-rose-600' : 'text-slate-600'}`} />
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
                  Monitored Host Daemon
                </span>
              </div>
              <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                isHostKilled 
                  ? 'bg-rose-100 text-rose-700 border-rose-300 animate-pulse' 
                  : 'bg-emerald-100 text-emerald-700 border-emerald-200'
              }`}>
                {isHostKilled ? '● FLATLINED' : '● ONLINE'}
              </span>
            </div>

            <div className="mt-1.5 flex items-baseline justify-between">
              <div>
                <div className="text-sm font-bold font-mono text-slate-900">prod-fin-vps01</div>
                <div className="text-[10px] text-slate-500">
                  {isHostKilled 
                    ? '3/3 Missed Pings (15s Silence) • Quarantined' 
                    : 'Go Agent <15MB RAM • 5s Sliding Ping'}
                </div>
              </div>
            </div>
          </div>

          {/* INTERACTIVE LOST HOST BUTTON - 1-CLICK TOGGLE */}
          <button
            onClick={onToggleHost}
            className={`mt-2 w-full py-1 px-2.5 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer shadow-xs ${
              isHostKilled
                ? 'bg-emerald-600 hover:bg-emerald-700 text-white'
                : 'bg-rose-600 hover:bg-rose-700 text-white'
            }`}
            title="Simulate attacker executing kill -9 to destroy host monitoring daemon"
          >
            {isHostKilled ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Restore Monitored Host</span>
              </>
            ) : (
              <>
                <Flame className="w-3.5 h-3.5" />
                <span>Simulate Lost Host (kill -9)</span>
              </>
            )}
          </button>
        </div>

        {/* CARD 3: THREAT CLASSIFICATION & INHERENT RISK (Screenshot 2 Stacked Risk) */}
        <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
              <div className="flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
                  Inherent Threat Risk
                </span>
              </div>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-rose-100 text-rose-700 border border-rose-200">
                CVSS 9.8
              </span>
            </div>

            <div className="mt-2">
              {/* Stacked Risk Progress Bar (Inspired by Screenshot 2) */}
              <div className="w-full h-2 rounded-full bg-slate-100 flex overflow-hidden">
                <div className="bg-rose-500 w-[65%]" title="Critical Risk 65%" />
                <div className="bg-amber-500 w-[20%]" title="High Risk 20%" />
                <div className="bg-yellow-400 w-[10%]" title="Medium Risk 10%" />
                <div className="bg-slate-300 w-[5%]" title="Low Risk 5%" />
              </div>

              <div className="mt-2 flex items-center justify-between text-[10px] font-sans">
                <span className="font-bold text-slate-900 truncate">
                  {activeScenario?.categoryTitle || 'Unauthorized Access'}
                </span>
                <span className="font-mono text-slate-500 text-[9px]">
                  {activeScenario?.ruleId}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-2 pt-1.5 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-500 font-sans">
            <span>Deterministic Sigma Match</span>
            <span className="text-emerald-600 font-semibold">0 Hallucination</span>
          </div>
        </div>

        {/* CARD 4: SENTRY EVIDENCE VAULT INTEGRITY */}
        <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-100">
              <div className="flex items-center gap-1.5">
                <Binary className="w-3.5 h-3.5 text-emerald-600" />
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">
                  Cryptographic Vault
                </span>
              </div>
              <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                tamperViolations > 0
                  ? 'bg-rose-100 text-rose-700 border-rose-200'
                  : 'bg-emerald-100 text-emerald-700 border-emerald-200'
              }`}>
                {tamperViolations > 0 ? 'CHAIN INVALID' : '100% VALID'}
              </span>
            </div>

            <div className="mt-1.5">
              <div className="flex items-baseline justify-between">
                <span className="text-xl font-bold font-mono text-slate-900">47 Records</span>
                <span className="text-[10px] font-mono text-slate-500">RFC 6962 SHA-256</span>
              </div>
              <p className="text-[10px] text-slate-500 mt-0.5">
                {isHostKilled 
                  ? 'Enclave Locked Read-Only • Zero Bit Alteration' 
                  : 'SQLite 3.45 WAL • Append-Only Stream'}
              </p>
            </div>
          </div>

          <div className="mt-2 pt-1.5 border-t border-slate-100 flex items-center justify-between">
            <button
              onClick={handleRunAudit}
              disabled={verifying}
              className="text-[11px] font-sans font-semibold text-emerald-700 hover:text-emerald-800 flex items-center gap-1 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'Verifying...' : 'Verify Hash Chain'}</span>
            </button>

            <button
              onClick={handleSimulateTamper}
              className="text-[10px] font-sans text-slate-400 hover:text-rose-600 transition-colors cursor-pointer"
              title="Test adversary bit-flip"
            >
              {tamperViolations > 0 ? 'Restore' : 'Bit-Flip Test'}
            </button>
          </div>
        </div>

      </div>

      {/* ========================================================================= */}
      {/* ROW 2: DUAL SPLIT WORKSPACE (FITS 100VH WITHOUT PAGE SCROLLING)           */}
      {/* ========================================================================= */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
        
        {/* LEFT COLUMN: INCIDENT PROCESS NARRATIVE & PITCH SEQUENCER (col-span-5) */}
        <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200/90 p-4 shadow-xs flex flex-col justify-between overflow-hidden">
          <div>
            {/* Header with Pitch Sequencer */}
            <div className="pb-2.5 border-b border-slate-100 mb-3">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-indigo-600" />
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700">
                    Incident Process Narrative
                  </h3>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold uppercase ${narrative.badgeStyle}`}>
                  {narrative.badge}
                </span>
              </div>

              {/* 5-Step Pitch Sequencer Strip (Directly includes Step 3: Lost Host) */}
              {onStepChange && (
                <div className="grid grid-cols-5 gap-1 bg-slate-50 p-1 rounded-lg border border-slate-200/80 font-mono text-[10px]">
                  {[
                    { step: 1, label: '1. Ingest' },
                    { step: 2, label: '2. Breach' },
                    { step: 3, label: '3. Lost Host' },
                    { step: 4, label: '4. Audit' },
                    { step: 5, label: '5. Report' }
                  ].map((s) => {
                    const isCurrent = currentStep === s.step;
                    return (
                      <button
                        key={s.step}
                        onClick={() => onStepChange(s.step)}
                        className={`py-1 px-1 rounded text-center transition-all cursor-pointer truncate ${
                          isCurrent
                            ? 'bg-indigo-600 text-white font-bold shadow-xs'
                            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/70'
                        }`}
                        title={`Stage Demo Step ${s.step}: ${s.label}`}
                      >
                        {s.label}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Executive Plain English Narrative */}
            <h4 className="text-sm font-bold font-sans text-slate-900 mb-1.5 leading-snug">
              {narrative.title}
            </h4>

            <p className="text-xs text-slate-600 font-sans leading-relaxed">
              {narrative.narrative}
            </p>
          </div>

          {/* 3 Quick Status Tiles & Annexure I CTA */}
          <div className="mt-3 pt-3 border-t border-slate-100 space-y-2.5">
            <div className="grid grid-cols-3 gap-2 text-xs font-sans">
              <div className="p-2 rounded-lg bg-slate-50 border border-slate-200/80">
                <span className="text-[9px] text-slate-500 uppercase font-mono block">Primary Host</span>
                <span className="text-xs font-bold text-slate-800 block truncate">prod-fin-vps01</span>
                <span className={isHostKilled ? "text-[10px] text-rose-600 font-semibold" : "text-[10px] text-emerald-600 font-semibold"}>
                  {isHostKilled ? "FLATLINED" : "ONLINE"}
                </span>
              </div>

              <div className="p-2 rounded-lg bg-slate-50 border border-slate-200/80">
                <span className="text-[9px] text-slate-500 uppercase font-mono block">Sentry Enclave</span>
                <span className="text-xs font-bold text-slate-800 block truncate">sentry-vault-01</span>
                <span className="text-[10px] text-emerald-600 font-semibold">
                  47 Records Sealed
                </span>
              </div>

              <div className="p-2 rounded-lg bg-slate-50 border border-slate-200/80">
                <span className="text-[9px] text-slate-500 uppercase font-mono block">CERT-In SLA</span>
                <span className="text-xs font-bold text-slate-800 block truncate">{activeScenario?.category}</span>
                <span className="text-[10px] text-amber-600 font-semibold">
                  Annexure I Ready
                </span>
              </div>
            </div>

            {/* Annexure I Button */}
            <button
              onClick={onOpenReport}
              className="group w-full py-2.5 px-3.5 rounded-xl bg-gradient-to-r from-slate-900 to-slate-800 hover:from-slate-800 hover:to-slate-700 text-white font-sans font-semibold text-xs transition-all shadow-md flex items-center justify-between cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-indigo-300" />
                <span>Open Pre-Populated CERT-In Annexure I Report</span>
              </div>
              <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center group-hover:translate-x-0.5 transition-transform">
                <ArrowUpRight className="w-3.5 h-3.5 text-white" />
              </div>
            </button>
          </div>
        </div>

        {/* RIGHT COLUMN: TECHNICAL FORENSIC CONSOLE (col-span-7) */}
        <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200/90 shadow-xs flex flex-col min-h-0 overflow-hidden">
          
          {/* Tab Bar */}
          <div className="px-3.5 py-2 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-2 shrink-0">
            <div className="flex items-center gap-1 font-mono text-xs">
              <button
                onClick={() => setActiveTab('FEED')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'FEED'
                    ? 'bg-white text-indigo-700 font-bold shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Telemetry Logs</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 border border-slate-200">
                  {events.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('VAULT')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'VAULT'
                    ? 'bg-white text-emerald-700 font-bold shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                }`}
              >
                <Binary className="w-3.5 h-3.5" />
                <span>Cryptographic Vault</span>
              </button>

              <button
                onClick={() => setActiveTab('DAG')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'DAG'
                    ? 'bg-white text-amber-700 font-bold shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                <span>Sigma DAG</span>
              </button>

              <button
                onClick={() => setActiveTab('INFRA')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === 'INFRA'
                    ? 'bg-white text-blue-700 font-bold shadow-xs border border-slate-200'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>Trust Topology</span>
              </button>
            </div>

            {/* Presidio Redaction Toggle */}
            <button
              onClick={onToggleMask}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border transition-colors cursor-pointer ${
                isPiiMasked 
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-700' 
                  : 'bg-amber-50 border-amber-200 text-amber-700'
              }`}
              title="Presidio PII Redaction Engine"
            >
              {isPiiMasked ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              <span className="text-[11px] font-semibold">{isPiiMasked ? 'Presidio Masked' : 'Raw Telemetry'}</span>
            </button>
          </div>

          {/* TAB 1: LIVE TELEMETRY LOGS */}
          {activeTab === 'FEED' && (
            <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
              
              {/* Filter & Search Bar */}
              <div className="px-3 py-2 border-b border-slate-100 bg-white flex items-center justify-between gap-3 shrink-0">
                <div className="flex items-center gap-1 font-mono text-[10px]">
                  {['ALL', 'AUTH', 'NGINX', 'CRITICAL'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setLogFilter(tab)}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        logFilter === tab
                          ? 'bg-slate-900 text-white font-semibold'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-1.5 bg-slate-50 px-2.5 py-1 rounded-lg border border-slate-200 w-52 sm:w-64">
                  <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <input
                    type="text"
                    placeholder="Search IP, user, hash..."
                    value={logSearch}
                    onChange={(e) => setLogSearch(e.target.value)}
                    className="w-full text-xs font-mono bg-transparent border-none text-slate-800 placeholder-slate-400 focus:outline-none"
                  />
                </div>
              </div>

              {/* Log Records Table (Internally scrollable, page stays fixed) */}
              <div className="flex-1 overflow-y-auto divide-y divide-slate-100 font-mono text-xs">
                {filteredEvents.map((ev) => {
                  const isSelected = selectedEvent?.id === ev.id;
                  return (
                    <div
                      key={ev.id}
                      onClick={() => onSelectEvent(ev)}
                      className={`px-3 py-2 transition-colors cursor-pointer hover:bg-slate-50 flex items-start gap-2.5 ${
                        isSelected ? 'bg-indigo-50/80 border-l-3 border-indigo-600' : ''
                      } ${ev.severity === 'CRITICAL' ? 'bg-rose-50/50' : ''}`}
                    >
                      <div className="w-14 shrink-0 text-[10px] text-slate-400">
                        <span className="text-slate-400 block">#{ev.id}</span>
                        <span className="text-slate-700 font-semibold">{ev.time}</span>
                      </div>

                      <div className="shrink-0 pt-0.5">
                        <span className={`text-[9px] uppercase px-1.5 py-0.2 rounded font-semibold border ${
                          ev.severity === 'CRITICAL'
                            ? 'bg-rose-100 text-rose-700 border-rose-200 font-bold'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}>
                          {ev.severity}
                        </span>
                      </div>

                      <div className="w-20 shrink-0 text-[10px] text-slate-500 truncate">
                        <span className="font-bold text-slate-700 block">{ev.facility}</span>
                        <span className="text-slate-400 text-[9px] block truncate">{ev.source}</span>
                      </div>

                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-slate-800 leading-snug break-all font-mono">
                          {isPiiMasked ? ev.redactedRaw : ev.raw}
                        </p>
                        <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-400">
                          <span>{ev.hash}</span>
                          <span>•</span>
                          <span className="text-emerald-700 font-semibold">Ed25519 Signed</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Log Detail Footer */}
              {selectedEvent && (
                <div className="px-3 py-1.5 border-t border-slate-100 bg-slate-50 text-[11px] font-mono text-slate-600 flex items-center justify-between shrink-0">
                  <div className="flex items-center gap-2 truncate">
                    <span className="font-bold text-slate-900">Event #{selectedEvent.id}:</span>
                    <span className="truncate">{selectedEvent.source} ({selectedEvent.facility})</span>
                  </div>
                  <span className="text-emerald-700 font-semibold shrink-0">
                    Annexure I Item 7 Evidence
                  </span>
                </div>
              )}

            </div>
          )}

          {/* TAB 2: CRYPTOGRAPHIC VAULT AUDIT */}
          {activeTab === 'VAULT' && (
            <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto font-mono text-xs">
              <div>
                <div className={`p-3.5 rounded-xl border mb-3.5 ${
                  auditResult.status === 'PASS'
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                    : 'bg-rose-50 border-rose-200 text-rose-800'
                }`}>
                  <div className="flex items-center justify-between font-bold">
                    <div className="flex items-center gap-2">
                      {auditResult.status === 'PASS' ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-rose-600" />
                      )}
                      <span>{auditResult.status === 'PASS' ? 'AUDIT PASSED • ZERO TAMPERING DETECTED' : 'AUDIT FAILED • TAMPER DETECTED'}</span>
                    </div>
                    <span className="text-xs font-normal text-slate-500">{auditResult.elapsedMs}ms Latency</span>
                  </div>
                  <p className="text-xs opacity-90 mt-1 font-sans text-slate-700">{auditResult.details}</p>
                </div>

                <div className="flex items-center gap-2 mb-4">
                  <button
                    onClick={handleRunAudit}
                    disabled={verifying}
                    className="flex-1 flex items-center justify-center gap-2 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-sans font-semibold text-xs transition-colors cursor-pointer disabled:opacity-50 shadow-xs"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
                    <span>{verifying ? 'Verifying SHA-256 Recursive Chain...' : 'Run Forensic Chain Verification'}</span>
                  </button>

                  <button
                    onClick={handleSimulateTamper}
                    className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-rose-50 text-slate-700 hover:text-rose-700 border border-slate-200 hover:border-rose-300 text-xs font-sans cursor-pointer transition-colors"
                  >
                    <Flame className="w-3.5 h-3.5 text-rose-600" />
                    <span>{tamperViolations > 0 ? 'Restore Authentic Chain' : 'Simulate Attacker Bit-Flip'}</span>
                  </button>
                </div>

                <h4 className="text-xs font-bold text-slate-800 mb-2 font-mono uppercase">
                  RFC 6962 SHA-256 Block Ledger Specs
                </h4>
                <div className="space-y-1.5 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <span className="text-slate-600">Genesis Root Hash:</span>
                    <span className="text-slate-900 font-mono font-bold">7a52e6ff74e2d3b4f621a364be16a5ef...</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <span className="text-slate-600">Storage Engine:</span>
                    <span className="text-slate-800 font-semibold">SQLite 3.45 (WAL Mode) + Append-Only NDJSON</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                    <span className="text-slate-600">Network Pathway:</span>
                    <span className="text-emerald-700 font-bold">Isolated Micro-VM • 0 Open Inbound Ports</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-100 text-xs text-slate-500 font-sans">
                Even with root compromise on the production server, adversaries have zero cryptographic capability or network routing to alter historical records sealed in the Sentry enclave.
              </div>
            </div>
          )}

          {/* TAB 3: SIGMA & ATT&CK PROVENANCE */}
          {activeTab === 'DAG' && (
            <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto text-xs font-sans">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="font-mono font-bold text-slate-900 uppercase">Deterministic Correlation Pipeline</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 font-semibold">
                    Zero LLM Hallucination
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                    <span className="text-slate-500 block text-[10px]">SIGMA RULE IDENTIFIER:</span>
                    <span className="text-indigo-700 font-bold">{activeScenario?.ruleId}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                    <span className="text-slate-500 block text-[10px]">INCIDENT SEVERITY:</span>
                    <span className="text-rose-600 font-bold">{activeScenario?.severity} (CVSS 9.8)</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 col-span-2">
                    <span className="text-slate-500 block text-[10px]">CORRELATION CONDITION:</span>
                    <span className="text-slate-800 font-semibold">{activeScenario?.ruleName}</span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] font-mono mb-1">MITRE ATT&CK TECHNIQUES:</span>
                  <div className="flex flex-wrap gap-1.5 font-mono">
                    {activeScenario?.mitreTechniques?.map((tech) => (
                      <span key={tech} className="px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 text-xs">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] font-mono mb-1">STATUTORY SECTION 70B MAPPING:</span>
                  <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-slate-800">
                    <span className="text-amber-800 font-bold block mb-1">
                      {activeScenario?.category}: {activeScenario?.categoryTitle}
                    </span>
                    <p className="text-xs text-slate-700 leading-relaxed">
                      Correlated telemetry feeds directly into CERT-In Annexure I Item 7 ("Chronological sequence of events") and Item 9 ("Root cause analysis") with verifiable SHA-256 evidence links.
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-100 text-xs text-slate-500">
                Rule evaluations execute in compiled Go code without stochastic LLM latency or hallucination risks.
              </div>
            </div>
          )}

          {/* TAB 4: TRUST TOPOLOGY & ENCLAVE ARCHITECTURE */}
          {activeTab === 'INFRA' && (
            <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto text-xs font-sans">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-100">
                  <span className="font-mono font-bold text-slate-900 uppercase">Dual Trust-Domain Architecture</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 font-semibold">
                    Strict Physical Isolation
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {/* Node 1 */}
                  <div className={`p-3.5 rounded-xl border transition-all ${
                    isHostKilled ? 'bg-rose-50 border-rose-300' : 'bg-slate-50 border-slate-200'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono font-bold text-slate-900">primary-srv-01</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                        isHostKilled ? 'bg-rose-100 text-rose-700' : 'bg-emerald-100 text-emerald-700'
                      }`}>
                        {isHostKilled ? 'FLATLINED' : 'ONLINE'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed mb-2">
                      Lightweight Go daemon running with &lt;15MB RAM footprint and &lt;2% CPU. Communicates outbound only over mTLS 1.3 with 0 open inbound ports.
                    </p>
                    <div className="font-mono text-[11px] text-slate-700 space-y-1">
                      <div>RAM: 12.4 MB</div>
                      <div>Outbound: mTLS 1.3</div>
                      <div>Heartbeat Seq: #{heartbeatSeq}</div>
                    </div>

                    <button
                      onClick={onToggleHost}
                      className={`mt-3 w-full py-1 px-2 rounded-lg text-xs font-sans font-semibold cursor-pointer ${
                        isHostKilled ? 'bg-emerald-600 text-white' : 'bg-rose-600 text-white'
                      }`}
                    >
                      {isHostKilled ? 'Restore Host Daemon' : 'Kill Daemon (kill -9)'}
                    </button>
                  </div>

                  {/* Node 2 */}
                  <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono font-bold text-slate-900">sentry-vault-01</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-700">
                        ARMED & SEALED
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed mb-2">
                      Isolated Black-Box micro-VM with SQLite 3.45 in Write-Ahead Log (WAL) mode. Contains recursive SHA-256 hash chains.
                    </p>
                    <div className="font-mono text-[11px] text-slate-700 space-y-1">
                      <div>Watchdog: 5s Sliding Window</div>
                      <div>Integrity: 0 Tampering</div>
                      <div>Dead-Man Switch: Armed</div>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-700 text-xs">
                  <span className="font-bold text-slate-900 block mb-0.5">Inverted Watchdog Mechanism:</span>
                  Sentry continuously listens for 5-second heartbeats. When an attacker kills the daemon (<code className="font-mono bg-slate-200 px-1 py-0.2 rounded text-slate-800">kill -9</code>), 3 missed pings (15s) automatically trigger <code className="font-mono bg-rose-100 px-1 py-0.2 rounded text-rose-800">SUSPECTED_COMPROMISE</code>, locking evidence in read-only mode.
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-100 text-xs text-slate-500">
                Dual-domain trust separation prevents compromised host credentials from modifying forensic vault records.
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
