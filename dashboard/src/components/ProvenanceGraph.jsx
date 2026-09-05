import React, { useState } from 'react';
import { 
  GitBranch, 
  ArrowDown, 
  CheckCircle2, 
  ShieldAlert, 
  Cpu, 
  FileText, 
  Zap,
  Terminal,
  Layers,
  ChevronRight
} from 'lucide-react';

export default function ProvenanceGraph({ scenarioData, onSelectStage }) {
  const activeScenario = scenarioData;
  const [selectedNode, setSelectedNode] = useState(2);

  const pipelineStages = [
    {
      step: 1,
      name: "1. Raw Log Ingestion",
      tag: `${activeScenario?.events?.length || 13} Vectors`,
      tagColor: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
      headline: "Egress-only mTLS telemetry collected from Linux kernel & services",
      meta: "journald • /var/log/auth.log • nginx/access.log",
      icon: Terminal
    },
    {
      step: 2,
      name: "2. Deterministic Sigma Engine",
      tag: activeScenario?.severity || "CRITICAL",
      tagColor: "bg-rose-500/15 text-rose-300 border-rose-500/40",
      headline: activeScenario?.ruleName || "High-Frequency Authentication Spray",
      meta: activeScenario?.mitreTechniques?.join(' • ') || "T1110.001 Password Spray • T1548 Sudo Root",
      icon: ShieldAlert
    },
    {
      step: 3,
      name: "3. Sentry Dead-Man's Switch",
      tag: "5s Window",
      tagColor: "bg-amber-500/15 text-amber-300 border-amber-500/40",
      headline: "Inverted Watchdog trips on 3 missed heartbeats (15s)",
      meta: "Quarantines host; isolates tamper-proof evidence vault in read-only mode",
      icon: Zap
    },
    {
      step: 4,
      name: "4. Cryptographic Vault Seal",
      tag: "SHA-256 Chained",
      tagColor: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
      headline: "Immutable NDJSON ledger indexed in SQLite WAL storage",
      meta: "47 records cryptographically validated against Genesis Root",
      icon: Layers
    },
    {
      step: 5,
      name: "5. Statutory Annexure-I Auto-Filing",
      tag: "Rule 70B Ready",
      tagColor: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      headline: `Statutory ${activeScenario?.category}: ${activeScenario?.categoryTitle}`,
      meta: "Pre-populated 12 fields + Presidio PII redaction + PGP .eml dispatch",
      icon: FileText
    }
  ];

  const handleNodeClick = (step) => {
    setSelectedNode(step);
    if (onSelectStage) onSelectStage(step);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-[#080d1a]/90 p-3.5 flex flex-col justify-between shadow-lg relative overflow-hidden">
      
      {/* Background Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a15_1px,transparent_1px),linear-gradient(to_bottom,#0f172a15_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none opacity-50" />

      {/* Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-slate-800/80 mb-2.5 shrink-0 relative z-10">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-rose-500/10 border border-rose-500/20 text-rose-400">
            <GitBranch className="w-3.5 h-3.5" />
          </div>
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-100 flex items-center gap-1.5">
              Attack Provenance DAG
            </h3>
            <p className="text-[10px] text-slate-400 font-sans">
              Deterministic causal progression (Zero-LLM hallucination)
            </p>
          </div>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-bold uppercase flex items-center gap-1">
          <CheckCircle2 className="w-2.5 h-2.5" />
          Provable Chain
        </span>
      </div>

      {/* 5-Node Vertical DAG Flow */}
      <div className="space-y-1.5 font-mono text-[10px] overflow-y-auto pr-1 relative z-10">
        {pipelineStages.map((stage, idx) => {
          const Icon = stage.icon;
          const isSelected = selectedNode === stage.step;
          return (
            <React.Fragment key={stage.step}>
              <div 
                onClick={() => handleNodeClick(stage.step)}
                className={`p-2 rounded-lg border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-[#0e1628] border-rose-500/50 shadow-[0_0_12px_rgba(225,29,72,0.15)] ring-1 ring-rose-500/30'
                    : 'bg-[#060a14] border-slate-800/80 hover:border-slate-700 hover:bg-[#0a0f1d]'
                }`}
              >
                <div className="flex items-center justify-between font-semibold mb-1">
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <Icon className={`w-3.5 h-3.5 ${isSelected ? 'text-rose-400' : 'text-slate-400'}`} />
                    <span className="font-bold">{stage.name}</span>
                  </div>
                  <span className={`text-[9px] px-1.5 py-0.2 rounded border font-mono ${stage.tagColor}`}>
                    {stage.tag}
                  </span>
                </div>
                <div className="text-white text-[11px] font-sans font-medium truncate">
                  {stage.headline}
                </div>
                <div className="text-[9px] text-slate-400 truncate mt-0.5">
                  {stage.meta}
                </div>
              </div>

              {idx < pipelineStages.length - 1 && (
                <div className="flex justify-center text-slate-600 my-0.2">
                  <ArrowDown className="w-2.5 h-2.5 text-slate-700" />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

    </div>
  );
}

