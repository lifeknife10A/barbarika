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
  Eye, 
  EyeOff, 
  Scale, 
  Lock,
  ArrowUpRight
} from 'lucide-react';

export default function StreamlinedDashboard({
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
  onTamperStatusChange
}) {
  // Lower forensic console tab: 'FEED' | 'VAULT' | 'DAG' | 'INFRA'
  const [activeTab, setActiveTab] = useState('FEED');
  
  // Log filtering
  const [logFilter, setLogFilter] = useState('ALL');
  const [logSearch, setLogSearch] = useState('');

  // Cryptographic audit state
  const [verifying, setVerifying] = useState(false);
  const [auditResult, setAuditResult] = useState({
    status: 'PASS',
    recordsCount: 47,
    elapsedMs: 42,
    details: 'All 47 records cryptographically verified against SHA-256 genesis root. Zero tampering detected.'
  });

  // Plain-English narrative for non-programmers (leadership, legal, judges)
  const getExecutiveNarrative = () => {
    switch (currentStep) {
      case 1:
        return {
          title: "System Nominal • Continuous Telemetry Ingestion Active",
          badge: "NOMINAL",
          badgeStyle: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
          narrative: "All monitored systems are functioning normally. The lightweight Go daemon (<15MB RAM) is tailing security logs with zero open inbound ports. The isolated Sentry vault is actively monitoring 5-second heartbeats.",
          action: "Routine monitoring active. No statutory reporting required."
        };
      case 2:
        return {
          title: "High-Frequency Intrusion Detected • 6-Hour Reporting Clock Active",
          badge: "THREAT DETECTED",
          badgeStyle: "bg-amber-500/15 text-amber-400 border-amber-500/30",
          narrative: `An external attacker is attempting high-frequency unauthorized access. Deterministic Sigma correlation matched rule ${activeScenario?.ruleId || 'SIGMA-CAT3-001'}. Classified under ${activeScenario?.category || 'Category III'} (${activeScenario?.categoryTitle || 'Unauthorized Access'}). The mandatory 6-hour Section 70B reporting deadline has started.`,
          action: "Drafting CERT-In Annexure I notice. Telemetry logs sealed in Sentry vault."
        };
      case 3:
        return {
          title: "Adversary Attacked Host • Sentry Dead-Man's Switch Engaged",
          badge: "HOST FLATLINED",
          badgeStyle: "bg-rose-500/15 text-rose-400 border-rose-500/30",
          narrative: "The attacker obtained root privileges and executed a force-kill (kill -9) on the monitoring agent to cover their tracks. Sentry's Inverted Watchdog detected 3 missed pings (15-second sliding window) and quarantined the host. All 47 evidence records remain completely intact in the isolated vault.",
          action: "Host quarantined. Sentry Vault locked in read-only forensic mode."
        };
      case 4:
        return {
          title: "Cryptographic Audit Verified • 0 Tampering Detected",
          badge: "AUDIT VERIFIED",
          badgeStyle: "bg-sky-500/15 text-sky-400 border-sky-500/30",
          narrative: "Cryptographic SHA-256 recursive chain verification completed across all SQLite WAL blocks. Genesis root validated. 47 historical records validated in 42ms with zero tampering detected, proving evidence survived the host destruction.",
          action: "Forensic evidence ready for statutory attestation and legal officer sign-off."
        };
      case 5:
        return {
          title: "Official Annexure I Prepared • Ready for Statutory Submission",
          badge: "COMPLIANCE READY",
          badgeStyle: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
          narrative: "All 12 statutory fields for CERT-In Annexure I have been automatically pre-populated from deterministic cryptographic logs. Customer PII has been redacted using Presidio. PGP-encrypted .eml dispatch packet is ready for dispatch to incident@cert-in.org.in.",
          action: "Human approval required. Click 'Generate Official Annexure I' to inspect and file."
        };
      default:
        return {
          title: "Monitoring Telemetry Stream",
          badge: "STANDBY",
          badgeStyle: "bg-slate-800 text-slate-300 border-slate-700",
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
          elapsedMs: 42,
          details: '47 records verified against SHA-256 genesis anchor. 0 tampering detected.'
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

  const isHostKilled = primaryNodeState === "KILLED";

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3 overflow-hidden text-slate-200">
      
      {/* ========================================================================= */}
      {/* UPPER SECTION: EXECUTIVE SLA COUNTDOWN & LIVE PROCESS NARRATIVE           */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 shrink-0">
        
        {/* CARD 1: STATUTORY 6-HOUR DEADLINE & COMPLIANCE ACTION (col-span-5) */}
        <div className="lg:col-span-5 bg-[#080d16]/90 backdrop-blur-xl rounded-2xl border border-white/10 p-4 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-white/5">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-amber-400" />
                <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Statutory 6-Hour SLA Window
                </h2>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-semibold ${
                isSlaActive 
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/30 animate-pulse' 
                  : 'bg-white/[0.04] text-slate-400 border-white/5'
              }`}>
                {isSlaActive ? '6H DEADLINE ACTIVE' : 'STANDBY'}
              </span>
            </div>

            <div className="my-3 flex items-baseline justify-between">
              <div>
                <div className={`text-3xl font-bold font-mono tracking-tight ${
                  isSlaActive ? 'text-amber-400' : 'text-slate-100'
                }`}>
                  {isSlaActive ? '05 : 58 : 32' : '06 : 00 : 00'}
                </div>
                <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                  Section 70B(6) IT Act Mandatory Notification Window
                </p>
              </div>
              <div className="text-right">
                <span className="text-[11px] font-mono font-bold px-2 py-1 rounded bg-white/[0.04] border border-white/10 text-slate-200 inline-block">
                  {activeScenario?.category || 'Category III'}
                </span>
                <span className="text-[10px] text-slate-400 font-mono block mt-0.5">
                  CERT-In Directions
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={onOpenReport}
            className="group mt-2 w-full flex items-center justify-between py-2 px-3.5 rounded-xl bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-400 hover:to-sky-500 text-white font-sans font-semibold text-xs transition-all shadow-lg shadow-sky-500/20 active:scale-[0.98] cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4" />
              <span>Generate Official CERT-In Annexure I Report</span>
            </div>
            <div className="w-6 h-6 rounded-full bg-white/20 flex items-center justify-center group-hover:translate-x-0.5 transition-transform">
              <ArrowUpRight className="w-3.5 h-3.5" />
            </div>
          </button>
        </div>

        {/* CARD 2: PLAIN-ENGLISH EXECUTIVE PROCESS SUMMARY (col-span-7) */}
        <div className="lg:col-span-7 bg-[#080d16]/90 backdrop-blur-xl rounded-2xl border border-white/10 p-4 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-white/5 mb-2.5">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-sky-400" />
                  <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                    Incident Process Narrative
                  </h3>
                </div>

                {onStepChange && (
                  <div className="hidden sm:flex items-center gap-1 bg-white/[0.04] p-0.5 rounded-lg border border-white/5 text-[10px] font-mono">
                    {[
                      { s: 1, label: '1. Ingest' },
                      { s: 2, label: '2. Breach' },
                      { s: 3, label: '3. Kill' },
                      { s: 4, label: '4. Audit' },
                      { s: 5, label: '5. Dispatch' }
                    ].map((step) => (
                      <button
                        key={step.s}
                        onClick={() => onStepChange(step.s)}
                        className={`px-2 py-0.5 rounded transition-all cursor-pointer ${
                          currentStep === step.s
                            ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40 font-bold'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                        title={`Stage Demo Step ${step.s}: ${step.label}`}
                      >
                        {step.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border font-bold uppercase ${narrative.badgeStyle}`}>
                {narrative.badge}
              </span>
            </div>

            <h4 className="text-sm font-semibold font-sans text-white mb-1.5 leading-snug">
              {narrative.title}
            </h4>

            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              {narrative.narrative}
            </p>
          </div>

          {/* 3 Quick Status Chips */}
          <div className="mt-3 pt-2.5 border-t border-white/5 grid grid-cols-3 gap-2 text-xs font-sans">
            <div className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Monitored Host</span>
              <span className="text-xs font-semibold text-white block truncate">prod-fin-vps01</span>
              <span className={isHostKilled ? "text-[10px] text-rose-400 font-semibold" : "text-[10px] text-emerald-400 font-semibold"}>
                {isHostKilled ? "FLATLINED (Quarantined)" : "Go Daemon <15MB RAM"}
              </span>
            </div>

            <div className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Sentry Vault</span>
              <span className="text-xs font-semibold text-white block truncate">sentry-vault-01</span>
              <span className="text-[10px] text-emerald-400 font-semibold">
                47 Records Sealed (0 Tampered)
              </span>
            </div>

            <div className="p-2 rounded-xl bg-white/[0.03] border border-white/5">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Statutory Filing</span>
              <span className="text-xs font-semibold text-white block truncate">{activeScenario?.category}</span>
              <span className="text-[10px] text-amber-300 font-semibold">
                Annexure I Draft Ready
              </span>
            </div>
          </div>

        </div>

      </div>

      {/* ========================================================================= */}
      {/* LOWER SECTION: TECHNICAL FORENSIC CONSOLE (FOR SOFTWARE ENGINEERS & SECOPS)*/}
      {/* ========================================================================= */}
      <div className="flex-1 min-h-0 bg-[#080d16]/90 backdrop-blur-xl rounded-2xl border border-white/10 shadow-xl flex flex-col overflow-hidden">
        
        {/* Navigation Tabs Bar */}
        <div className="px-4 py-2 border-b border-white/10 bg-white/[0.02] flex flex-wrap items-center justify-between gap-2 shrink-0">
          
          {/* Tabs */}
          <div className="flex items-center gap-1 font-mono text-xs">
            <button
              onClick={() => setActiveTab('FEED')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTab === 'FEED'
                  ? 'bg-white/10 text-white font-bold border border-white/15 shadow-inner'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-sky-400" />
              <span>Telemetry Logs</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-white/10 text-slate-300 font-mono border border-white/10">
                {events.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('VAULT')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTab === 'VAULT'
                  ? 'bg-white/10 text-white font-bold border border-white/15 shadow-inner'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <Binary className="w-3.5 h-3.5 text-emerald-400" />
              <span>Cryptographic Vault</span>
            </button>

            <button
              onClick={() => setActiveTab('DAG')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTab === 'DAG'
                  ? 'bg-white/10 text-white font-bold border border-white/15 shadow-inner'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5 text-amber-400" />
              <span>Sigma & Provenance</span>
            </button>

            <button
              onClick={() => setActiveTab('INFRA')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTab === 'INFRA'
                  ? 'bg-white/10 text-white font-bold border border-white/15 shadow-inner'
                  : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
              }`}
            >
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Trust Topology</span>
            </button>
          </div>

          {/* Presidio Redaction Button */}
          <button
            onClick={onToggleMask}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border transition-colors cursor-pointer ${
              isPiiMasked 
                ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300' 
                : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
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
            <div className="px-4 py-2 border-b border-white/5 bg-[#070b13] flex items-center justify-between gap-3 shrink-0">
              <div className="flex items-center gap-1 font-mono text-[10px]">
                {['ALL', 'AUTH', 'NGINX', 'CRITICAL'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setLogFilter(tab)}
                    className={`px-2.5 py-0.5 rounded-md transition-colors cursor-pointer ${
                      logFilter === tab
                        ? 'bg-sky-500/20 text-sky-300 font-semibold border border-sky-500/30'
                        : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5 bg-[#05080e] px-2.5 py-1 rounded-lg border border-white/10 w-56 sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <input
                  type="text"
                  placeholder="Filter logs by IP, user, hash..."
                  value={logSearch}
                  onChange={(e) => setLogSearch(e.target.value)}
                  className="w-full text-xs font-mono bg-transparent border-none text-slate-200 placeholder-slate-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Log Table (Internally scrollable, dashboard stays fixed) */}
            <div className="flex-1 overflow-y-auto divide-y divide-white/5 font-mono text-xs">
              {filteredEvents.map((ev) => {
                const isSelected = selectedEvent?.id === ev.id;
                return (
                  <div
                    key={ev.id}
                    onClick={() => onSelectEvent(ev)}
                    className={`px-4 py-2.5 transition-colors cursor-pointer hover:bg-white/[0.03] flex items-start gap-3 ${
                      isSelected ? 'bg-sky-500/10 border-l-2 border-sky-400' : ''
                    } ${ev.severity === 'CRITICAL' ? 'bg-rose-500/5' : ''}`}
                  >
                    <div className="w-14 shrink-0 text-[10px] text-slate-400">
                      <span className="text-slate-500 block">#{ev.id}</span>
                      <span className="text-slate-300 font-semibold">{ev.time}</span>
                    </div>

                    <div className="shrink-0 pt-0.5">
                      <span className={`text-[9px] uppercase px-1.5 py-0.2 rounded font-semibold border ${
                        ev.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/30 font-bold'
                          : 'bg-white/[0.04] text-slate-400 border-white/10'
                      }`}>
                        {ev.severity}
                      </span>
                    </div>

                    <div className="w-20 shrink-0 text-[10px] text-slate-400 truncate">
                      <span className="font-bold text-sky-400 block">{ev.facility}</span>
                      <span className="text-slate-500 text-[9px] block truncate">{ev.source}</span>
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-200 leading-snug break-all font-mono">
                        {isPiiMasked ? ev.redactedRaw : ev.raw}
                      </p>
                      <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                        <span>{ev.hash}</span>
                        <span>•</span>
                        <span className="text-emerald-400 font-semibold">Ed25519 Validated</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Log Detail Footer */}
            {selectedEvent && (
              <div className="px-4 py-2 border-t border-white/5 bg-[#05080e] text-xs font-mono text-slate-400 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2 truncate">
                  <span className="font-bold text-white">Event #{selectedEvent.id}:</span>
                  <span className="text-slate-300 truncate">{selectedEvent.source} ({selectedEvent.facility})</span>
                </div>
                <span className="text-emerald-400 font-semibold shrink-0">
                  Valid for Annexure I Item 7
                </span>
              </div>
            )}

          </div>
        )}

        {/* TAB 2: CRYPTOGRAPHIC VAULT AUDIT & TAMPER PROOF */}
        {activeTab === 'VAULT' && (
          <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto font-mono text-xs">
            <div>
              {/* Audit Status Banner */}
              <div className={`p-3.5 rounded-xl border mb-3.5 ${
                auditResult.status === 'PASS'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              }`}>
                <div className="flex items-center justify-between font-bold">
                  <div className="flex items-center gap-2">
                    {auditResult.status === 'PASS' ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                    )}
                    <span>{auditResult.status === 'PASS' ? 'AUDIT PASSED • ZERO TAMPERING DETECTED' : 'AUDIT FAILED • TAMPER DETECTED'}</span>
                  </div>
                  <span className="text-xs font-normal text-slate-400">{auditResult.elapsedMs}ms Audit Latency</span>
                </div>
                <p className="text-xs opacity-90 mt-1 font-sans text-slate-300">{auditResult.details}</p>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 mb-4">
                <button
                  onClick={handleRunAudit}
                  disabled={verifying}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-sans font-semibold text-xs transition-colors cursor-pointer disabled:opacity-50 shadow-lg shadow-emerald-600/20"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
                  <span>{verifying ? 'Verifying SHA-256 Recursive Chain...' : 'Run Forensic Chain Verification'}</span>
                </button>

                <button
                  onClick={handleSimulateTamper}
                  className="flex items-center gap-1.5 px-3.5 py-2.5 rounded-xl bg-white/[0.04] hover:bg-rose-500/20 text-slate-300 hover:text-rose-300 border border-white/10 hover:border-rose-500/30 text-xs font-sans cursor-pointer transition-colors"
                  title="Simulates adversary tampering with 1 bit in block #5 on the host to demonstrate instant chain invalidation"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>{tamperViolations > 0 ? 'Restore Authentic Chain' : 'Simulate Attacker Bit-Flip'}</span>
                </button>
              </div>

              {/* Ledger Summary */}
              <h4 className="text-xs font-bold text-slate-200 mb-2 font-mono uppercase">
                Cryptographic Block Ledger Specs (RFC 6962 SHA-256)
              </h4>
              <div className="space-y-1.5 text-xs">
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between">
                  <span className="text-slate-400">Genesis Root Hash:</span>
                  <span className="text-sky-300 font-mono font-bold">7a52e6ff74e2d3b4f621a364be16a5ef...</span>
                </div>
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between">
                  <span className="text-slate-400">Storage Engine:</span>
                  <span className="text-slate-200 font-semibold">SQLite 3.45 (Write-Ahead Logging) + Append-Only NDJSON</span>
                </div>
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between">
                  <span className="text-slate-400">Network Pathway:</span>
                  <span className="text-emerald-400 font-bold">Isolated Micro-VM • 0 Inbound Open Ports</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 text-xs text-slate-400 font-sans">
              Even with root privilege compromise on the production server, adversaries have zero cryptographic capability or network routing to alter historical logs sealed in the Sentry enclave.
            </div>
          </div>
        )}

        {/* TAB 3: DETERMINISTIC SIGMA & ATTACK PROVENANCE */}
        {activeTab === 'DAG' && (
          <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto text-xs font-sans">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-white/5">
                <span className="font-mono font-bold text-white uppercase">Deterministic Correlation Pipeline</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold">
                  Zero LLM Hallucination
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5">
                  <span className="text-slate-500 block text-[10px]">SIGMA RULE IDENTIFIER:</span>
                  <span className="text-sky-300 font-bold">{activeScenario?.ruleId}</span>
                </div>
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5">
                  <span className="text-slate-500 block text-[10px]">INCIDENT SEVERITY:</span>
                  <span className="text-rose-400 font-bold">{activeScenario?.severity} (CVSS 9.8)</span>
                </div>
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/5 col-span-2">
                  <span className="text-slate-500 block text-[10px]">CORRELATION CONDITION:</span>
                  <span className="text-slate-200 font-semibold">{activeScenario?.ruleName}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] font-mono mb-1">MITRE ATT&CK FRAMEWORK TACTICS:</span>
                <div className="flex flex-wrap gap-1.5 font-mono">
                  {activeScenario?.mitreTechniques?.map((tech) => (
                    <span key={tech} className="px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/10 text-slate-300 text-xs">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] font-mono mb-1">STATUTORY SECTION 70B MAPPING:</span>
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-slate-300">
                  <span className="text-amber-300 font-bold block mb-1">
                    {activeScenario?.category}: {activeScenario?.categoryTitle}
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Correlated telemetry feeds directly into CERT-In Annexure I Item 7 ("Chronological sequence of events") and Item 9 ("Root cause analysis") with verifiable SHA-256 evidence links.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 text-xs text-slate-400">
              Rule evaluations execute in deterministic Go code without stochastic LLM latency or hallucination risks.
            </div>
          </div>
        )}

        {/* TAB 4: DUAL TRUST-DOMAIN INFRASTRUCTURE */}
        {activeTab === 'INFRA' && (
          <div className="flex-1 p-4 flex flex-col justify-between overflow-y-auto text-xs font-sans">
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-white/5">
                <span className="font-mono font-bold text-white uppercase">Dual Trust-Domain Architecture</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold">
                  Strict Physical Isolation
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {/* Node 1 */}
                <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono font-bold text-white">primary-srv-01</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                      isHostKilled ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                    }`}>
                      {isHostKilled ? 'FLATLINED' : 'ONLINE'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed mb-2">
                    Lightweight Go daemon running with &lt;15MB RAM footprint and &lt;2% CPU. Communicates outbound only over mTLS 1.3 with 0 open inbound ports.
                  </p>
                  <div className="font-mono text-[11px] text-slate-300 space-y-1">
                    <div>RAM: 12.4 MB</div>
                    <div>Outbound: mTLS 1.3</div>
                    <div>Heartbeat Seq: #{heartbeatSeq}</div>
                  </div>
                </div>

                {/* Node 2 */}
                <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono font-bold text-white">sentry-vault-01</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-300">
                      ARMED & SEALED
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed mb-2">
                    Isolated Black-Box micro-VM with SQLite 3.45 in Write-Ahead Log (WAL) mode. Contains recursive SHA-256 hash chains.
                  </p>
                  <div className="font-mono text-[11px] text-slate-300 space-y-1">
                    <div>Watchdog: 5s Sliding Window</div>
                    <div>Integrity: 0 Tampering</div>
                    <div>Dead-Man Switch: Armed</div>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5 text-slate-300 text-xs">
                <span className="font-bold text-white block mb-0.5">Inverted Watchdog Mechanism:</span>
                Sentry continuously listens for 5-second heartbeats. When an attacker kills the daemon (<code className="font-mono bg-white/10 px-1 py-0.2 rounded text-white">kill -9</code>), 3 missed pings (15s) automatically trigger <code className="font-mono bg-white/10 px-1 py-0.2 rounded text-white">SUSPECTED_COMPROMISE</code>, locking evidence in read-only mode.
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 text-xs text-slate-500">
              Dual-domain trust separation prevents compromised host credentials from modifying forensic vault records.
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
