import React, { useState, useEffect, useCallback } from 'react';

import TopNavbar from './components/TopNavbar';
import CleanWhiteDashboard from './components/CleanWhiteDashboard';
import MinimalDashboard from './components/MinimalDashboard';
import DualNodeStatus from './components/DualNodeStatus';
import LiveIngestFeed from './components/LiveIngestFeed';
import ProvenanceGraph from './components/ProvenanceGraph';
import HashChainVerifier from './components/HashChainVerifier';
import AnnexureIModal from './components/AnnexureIModal';

import { 
  INITIAL_NODES, 
  DETECTION_PATHS, 
  INITIAL_HASH_CHAIN 
} from './data/mockIncidents';

import { 
  Shield, 
  Server, 
  Lock, 
  GitBranch, 
  Binary, 
  CheckCircle2, 
  AlertTriangle,
  Code2,
  FileText,
  Activity
} from 'lucide-react';

export default function App() {
  // Scenario state: CAT3 | CAT10 | CAT5
  const [currentScenarioKey, setCurrentScenarioKey] = useState("CAT3");
  const activeScenario = DETECTION_PATHS[currentScenarioKey];

  // Menu navigation view: 'ALL' (Clean White Dashboard) | 'FEED' | 'PROVENANCE' | 'VAULT' | 'INFRA'
  const [activeView, setActiveView] = useState('ALL');

  // Stage demo step (1 to 5)
  const [currentStep, setCurrentStep] = useState(1);
  
  // Incident & SLA state
  const [isSlaActive, setIsSlaActive] = useState(false);
  const [primaryNodeState, setPrimaryNodeState] = useState("HEALTHY"); // HEALTHY | COMPROMISED | KILLED
  const [watchdogState, setWatchdogState] = useState("WATCHING"); // WATCHING | SUSPECTED_COMPROMISE
  const [heartbeatSeq, setHeartbeatSeq] = useState(1842);
  const [tamperViolations, setTamperViolations] = useState(0);

  // Evidence and logs
  const [events, setEvents] = useState(activeScenario.events);
  const [selectedEvent, setSelectedEvent] = useState(activeScenario.events[activeScenario.events.length - 2]);
  const [isPiiMasked, setIsPiiMasked] = useState(true);

  // Persona view mode: 'CISO' (Executive) | 'SECOPS' (Engineering)
  const [personaMode, setPersonaMode] = useState("CISO");

  // Modal state
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  // Synchronize events when scenario changes
  useEffect(() => {
    setEvents(activeScenario.events);
    setSelectedEvent(activeScenario.events[activeScenario.events.length - 2] || activeScenario.events[0]);
  }, [currentScenarioKey, activeScenario]);

  // Heartbeat sequence ticker
  useEffect(() => {
    if (primaryNodeState === "KILLED") return;
    const interval = setInterval(() => {
      setHeartbeatSeq((prev) => prev + 1);
    }, 5000);
    return () => clearInterval(interval);
  }, [primaryNodeState]);

  // Stage demo coordinator for 3-minute hackathon pitch
  const handleStageStep = useCallback((stepNumber) => {
    setCurrentStep(stepNumber);

    if (stepNumber === 1) {
      setIsSlaActive(false);
      setPrimaryNodeState("HEALTHY");
      setWatchdogState("WATCHING");
      setIsReportModalOpen(false);
    } else if (stepNumber === 2) {
      setIsSlaActive(true);
      setPrimaryNodeState("COMPROMISED");
      setWatchdogState("WATCHING");
      setIsReportModalOpen(false);
    } else if (stepNumber === 3) {
      setIsSlaActive(true);
      setPrimaryNodeState("KILLED");
      setWatchdogState("SUSPECTED_COMPROMISE");
      setIsReportModalOpen(false);
    } else if (stepNumber === 4) {
      setIsSlaActive(true);
      setPrimaryNodeState("KILLED");
      setWatchdogState("SUSPECTED_COMPROMISE");
      setIsReportModalOpen(false);
    } else if (stepNumber === 5) {
      setIsSlaActive(true);
      setPrimaryNodeState("KILLED");
      setWatchdogState("SUSPECTED_COMPROMISE");
      setIsReportModalOpen(true);
    }
  }, []);

  const handleToggleHostState = () => {
    if (primaryNodeState === "KILLED") {
      setPrimaryNodeState("HEALTHY");
      setWatchdogState("WATCHING");
      setCurrentStep(1);
    } else {
      setPrimaryNodeState("KILLED");
      setWatchdogState("SUSPECTED_COMPROMISE");
      setIsSlaActive(true);
      setCurrentStep(3);
    }
  };

  const handleResetStage = () => {
    handleStageStep(1);
  };

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#f8fafc] text-slate-800 flex flex-col font-sans select-none">
      
      {/* Top Header with Brand and Clean Actions (Statutory Banner removed as requested) */}
      <TopNavbar
        isPiiMasked={isPiiMasked}
        onToggleMask={() => setIsPiiMasked(!isPiiMasked)}
        onOpenReport={() => setIsReportModalOpen(true)}
      />

      {/* 3. Main Dynamic Workspace (Strictly fits 100vh with NO vertical page scrolling) */}
      <main className="flex-1 min-h-0 overflow-hidden p-2.5 sm:p-3 flex flex-col">
        
        {/* VIEW 1: CLEAN WHITE DASHBOARD (SYSTEM HEALTH, EPM GRAPH, INCOMING LOGS) */}
        {activeView === 'ALL' && (
          <CleanWhiteDashboard
            onOpenReport={() => setIsReportModalOpen(true)}
          />
        )}

        {/* VIEW 2: LIVE TELEMETRY (FOCUSED TELEMETRY STREAM & INSPECTOR) */}
        {activeView === 'FEED' && (
          <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
            <div className="lg:col-span-7 flex flex-col min-h-0 overflow-hidden">
              <LiveIngestFeed
                events={events}
                selectedEventId={selectedEvent?.id}
                onSelectEvent={(ev) => setSelectedEvent(ev)}
                isMasked={isPiiMasked}
              />
            </div>
            <div className="lg:col-span-5 flex flex-col min-h-0 overflow-hidden rounded-lg border border-slate-800 bg-[#090d16] p-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-3">
                <div className="flex items-center gap-2 font-mono">
                  <Activity className="w-4 h-4 text-sky-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Telemetry Event Inspector
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-slate-400">
                  Event #{selectedEvent?.id || '---'}
                </span>
              </div>

              {selectedEvent ? (
                <div className="space-y-3 font-mono text-xs overflow-y-auto flex-1 pr-1">
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                      <span className="text-slate-500 block text-[10px]">TIMESTAMP:</span>
                      <span className="text-slate-200 font-semibold">{selectedEvent.time}</span>
                    </div>
                    <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                      <span className="text-slate-500 block text-[10px]">SEVERITY:</span>
                      <span className={selectedEvent.severity === 'CRITICAL' ? 'text-rose-400 font-bold' : 'text-amber-400 font-bold'}>
                        {selectedEvent.severity}
                      </span>
                    </div>
                    <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                      <span className="text-slate-500 block text-[10px]">FACILITY / LOG:</span>
                      <span className="text-sky-300 font-semibold">{selectedEvent.facility} ({selectedEvent.source})</span>
                    </div>
                    <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                      <span className="text-slate-500 block text-[10px]">SIGNATURE:</span>
                      <span className="text-emerald-400 font-semibold">Ed25519 Valid</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] mb-1">
                      LOG PAYLOAD ({isPiiMasked ? 'PRESIDIO PII REDACTED' : 'RAW OS TELEMETRY'}):
                    </span>
                    <div className="p-2.5 rounded bg-[#06090f] border border-slate-800 text-[11px] text-slate-300 break-all leading-relaxed font-mono">
                      {isPiiMasked ? selectedEvent.redactedRaw : selectedEvent.raw}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] mb-1">CRYPTOGRAPHIC RECORD DIGEST:</span>
                    <div className="p-2 rounded bg-[#06090f] border border-slate-800 text-[10px] text-slate-400 font-mono break-all">
                      {selectedEvent.hash}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-sky-950/20 border border-sky-800/40 text-[11px] font-sans">
                    <span className="text-sky-300 font-semibold block mb-0.5">Section 70B Relevance:</span>
                    <p className="text-slate-300 text-[11px]">
                      This telemetry event constitutes verifiable digital evidence for CERT-In Annexure I Item 7 ("Chronological sequence of events") and Item 9 ("Root cause / attack vector").
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center text-slate-500 font-mono text-xs">
                  Select an event from the feed to inspect details.
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 3: PROVENANCE DAG (FOCUSED CORRELATION PIPELINE) */}
        {activeView === 'PROVENANCE' && (
          <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
            <div className="lg:col-span-5 flex flex-col min-h-0 overflow-hidden">
              <ProvenanceGraph scenarioData={activeScenario} />
            </div>
            <div className="lg:col-span-7 flex flex-col min-h-0 overflow-hidden rounded-lg border border-slate-800 bg-[#090d16] p-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-3">
                <div className="flex items-center gap-2 font-mono">
                  <GitBranch className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Deterministic Sigma Correlation Engine
                  </h3>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                  Zero LLM Hallucination Risk
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs overflow-y-auto flex-1 pr-1">
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">RULE IDENTIFIER:</span>
                    <span className="text-sky-300 font-bold">{activeScenario.ruleId}</span>
                  </div>
                  <div className="p-2 rounded bg-[#06090f] border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">RULE SEVERITY:</span>
                    <span className="text-rose-400 font-bold">{activeScenario.severity}</span>
                  </div>
                  <div className="p-2 rounded bg-[#06090f] border border-slate-800 col-span-2">
                    <span className="text-slate-500 block text-[10px]">CORRELATION RULE NAME:</span>
                    <span className="text-slate-200 font-semibold">{activeScenario.ruleName}</span>
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] mb-1">MITRE ATT&CK FRAMEWORK MAPPINGS:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {activeScenario.mitreTechniques?.map((tech) => (
                      <span key={tech} className="px-2 py-1 rounded bg-[#06090f] border border-slate-800 text-[10px] text-slate-300">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block text-[10px] mb-1">STATUTORY SECTION 70B MAPPING:</span>
                  <div className="p-3 rounded bg-amber-950/20 border border-amber-900/40 text-[11px] font-sans">
                    <div className="flex items-center justify-between font-mono font-bold text-amber-300 mb-1">
                      <span>{activeScenario.category}</span>
                      <span>{activeScenario.statutoryRef}</span>
                    </div>
                    <p className="text-slate-300 text-xs leading-relaxed">
                      {activeScenario.categoryTitle}. Triggers mandatory 6-hour statutory notification to CERT-In pursuant to Rule 12(1)(a) of Information Technology Rules 2013.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 4: EVIDENCE VAULT (FOCUSED CRYPTOGRAPHIC VERIFIER & LEDGER) */}
        {activeView === 'VAULT' && (
          <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
            <div className="lg:col-span-4 flex flex-col min-h-0 overflow-hidden">
              <HashChainVerifier
                records={INITIAL_HASH_CHAIN}
                onTamperStatusChange={(count) => setTamperViolations(count)}
              />
            </div>
            <div className="lg:col-span-8 flex flex-col min-h-0 overflow-hidden rounded-lg border border-slate-800 bg-[#090d16] p-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-3">
                <div className="flex items-center gap-2 font-mono">
                  <Binary className="w-4 h-4 text-sky-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Sentry Cryptographic Hash Chain Ledger (SHA-256)
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-slate-400">
                  47 Blocks Indexed • Genesis Anchor Active
                </span>
              </div>

              <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 font-mono text-[11px]">
                {INITIAL_HASH_CHAIN.map((record) => (
                  <div key={record.seq} className="py-2 px-2 hover:bg-slate-900/40 flex items-center justify-between gap-4">
                    <div className="w-12 text-slate-500 shrink-0">#{record.seq}</div>
                    <div className="w-20 text-slate-400 shrink-0 text-[10px]">{record.timestamp}</div>
                    <div className="flex-1 truncate text-slate-300 font-sans text-xs">
                      {record.eventSummary}
                    </div>
                    <div className="w-32 truncate text-slate-500 text-[10px]">
                      {record.currHash}
                    </div>
                    <div className="shrink-0">
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-semibold">
                        VERIFIED
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* VIEW 5: TOPOLOGY NODES (FOCUSED DUAL TRUST-DOMAIN SPECS) */}
        {activeView === 'INFRA' && (
          <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-2.5 overflow-hidden">
            <div className="lg:col-span-5 flex flex-col min-h-0 overflow-hidden">
              <DualNodeStatus
                primaryState={primaryNodeState}
                watchdogState={watchdogState}
                heartbeatCount={heartbeatSeq}
                recordsIndexed={47}
                tamperCount={tamperViolations}
              />
            </div>
            <div className="lg:col-span-7 flex flex-col min-h-0 overflow-hidden rounded-lg border border-slate-800 bg-[#090d16] p-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-3">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-sky-400" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                    Dual Trust-Domain Security Architecture
                  </h3>
                </div>
                <span className="text-[10px] text-emerald-400">
                  Strict Isolation Active
                </span>
              </div>

              <div className="space-y-3 overflow-y-auto flex-1 pr-1 font-sans text-xs">
                <div className="p-3 rounded bg-[#06090f] border border-slate-800">
                  <h4 className="font-mono font-bold text-sky-400 text-xs mb-1">
                    Primary Production Host (Node 1)
                  </h4>
                  <p className="text-slate-300 text-xs leading-relaxed">
                    Runs the ultra-lightweight Go telemetry agent with a footprint of &lt;15MB RAM and &lt;2% CPU. The agent communicates strictly outbound over mutual TLS 1.3 with zero open inbound listening ports, making remote compromise of the daemon impossible.
                  </p>
                </div>

                <div className="p-3 rounded bg-[#06090f] border border-slate-800">
                  <h4 className="font-mono font-bold text-emerald-400 text-xs mb-1">
                    Isolated Black-Box Sentry Enclave (Node 2)
                  </h4>
                  <p className="text-slate-300 text-xs leading-relaxed">
                    Separated physically or logically in a hardened micro-VM. Contains SQLite 3.45 in write-ahead log (WAL) mode with recursive SHA-256 chaining. Even if root privileges are obtained on Node 1, the attacker has no network pathway or credentials to tamper with Sentry logs.
                  </p>
                </div>

                <div className="p-3 rounded bg-rose-950/20 border border-rose-900/40">
                  <h4 className="font-mono font-bold text-rose-300 text-xs mb-1">
                    Inverted Watchdog (Dead-Man's Switch)
                  </h4>
                  <p className="text-slate-300 text-xs leading-relaxed">
                    Sentry continuously listens for 5-second heartbeats from Node 1. If an adversary terminates the Go daemon (<code className="font-mono bg-rose-950/80 px-1 py-0.5 rounded text-rose-200">kill -9</code>) after an intrusion, 3 missed heartbeats (15s sliding window) automatically trigger the <code className="font-mono bg-rose-950/80 px-1 py-0.5 rounded text-rose-200">SUSPECTED_COMPROMISE</code> state, preserving evidence and alerting the CISO.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* 4. Official CERT-In Annexure I Modal */}
      <AnnexureIModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        currentScenario={currentScenarioKey}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-1.5 px-4 text-[11px] font-sans text-slate-500 shrink-0 flex items-center justify-between shadow-xs">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
          <span className="text-slate-900 font-bold font-sans">BARBARIKA</span>
        </div>

        <div className="flex items-center gap-2 text-[10px] text-slate-400 font-sans">
          <span className="text-emerald-600 font-medium">System Online</span>
        </div>
      </footer>

    </div>
  );
}

