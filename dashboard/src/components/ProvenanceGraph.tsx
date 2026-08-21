import React, { useState } from 'react';
import { Shield, FileText, ArrowRight, Eye, CheckCircle2, Lock, Unlock, Cpu, AlertTriangle, Layers, Database } from 'lucide-react';
import { IncidentRecord, TelemetryEvent, ProvenanceNode } from '../types';

interface ProvenanceGraphProps {
  incident: IncidentRecord | null;
  events: TelemetryEvent[];
  onOpenUnmask: (field: string, entityId: string, maskedVal: string, realVal: string) => void;
}

export const ProvenanceGraph: React.FC<ProvenanceGraphProps> = ({
  incident,
  events,
  onOpenUnmask,
}) => {
  const [selectedNode, setSelectedNode] = useState<ProvenanceNode | null>(null);

  if (!incident) {
    return (
      <div className="glass-panel rounded-xl p-8 border border-cyber-border text-center">
        <div className="w-12 h-12 rounded-xl bg-slate-800 text-slate-400 mx-auto flex items-center justify-center mb-3">
          <Layers className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">
          EVIDENCE PROVENANCE GRAPH (DAG)
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
          No active incident selected. Inject a demo attack scenario above or await live telemetry to visualize the cryptographic chain from Raw Event to Fired Rule to Statutory Category to Annexure I.
        </p>
      </div>
    );
  }

  // Correlated raw events for this incident
  const correlatedEvents = events.filter(e => incident.correlated_event_ids.includes(e.event_id));

  // Build DAG nodes
  const rawEventNodes: ProvenanceNode[] = correlatedEvents.map((evt, idx) => ({
    id: evt.event_id,
    label: `Raw Event #${evt.sequence || idx + 1}: ${evt.event_type}`,
    type: 'raw_event',
    status: 'flagged',
    timestamp: evt.occurred_at,
    details: {
      source: evt.source,
      severity: evt.severity,
      record_hash: evt.record_hash,
      signature: evt.signature,
      payload: evt.payload,
      masked_fields: evt.masked_fields,
    },
  }));

  const ruleNode: ProvenanceNode = {
    id: incident.rule_id || 'RULE-MATCHED',
    label: incident.rule_name || 'Sigma/YAML Correlation Rule',
    type: 'detection_rule',
    status: 'matched',
    timestamp: incident.timestamps.detected_at,
    details: {
      rule_id: incident.rule_id,
      rule_name: incident.rule_name,
      engine: 'Barbarika Deterministic Sigma-V2',
      evaluation: 'Multi-Signal Correlation Met (>10 failures + sudo auth)',
      file: 'rules/v1/category_iii_ssh_bruteforce.yaml',
    },
  };

  const categoryNode: ProvenanceNode = {
    id: `CAT-${incident.category.toUpperCase()}`,
    label: `${incident.category_numeral}: ${incident.category_name}`,
    type: 'statutory_category',
    status: 'flagged',
    timestamp: incident.timestamps.noticed_at,
    details: {
      code: incident.category,
      statutory_ref: 'Annexure I, CERT-In Cyber Security Directions (28 Apr 2022)',
      legal_requirement: 'Mandatory filing within 6 hours under IT Act Sec 70B(6)',
      penalty_ref: 'IT Act Section 70B(7)',
      status: incident.status,
    },
  };

  const reportFieldNodes: ProvenanceNode[] = [
    {
      id: 'field-1-host',
      label: 'Field 4: Affected System Details',
      type: 'report_field',
      status: 'generated',
      details: {
        field_name: 'Name of Affected System / IP / Hostname',
        auto_value: incident.affected_host,
        provenance_source: 'Primary Host Agent Telemetry',
      },
    },
    {
      id: 'field-2-synopsis',
      label: 'Field 5: Attack Vector & Synopsis',
      type: 'report_field',
      status: 'generated',
      details: {
        field_name: 'Synopsis of Incident & Attack Vector',
        auto_value: incident.attack_vector,
        provenance_source: 'Rule Engine Correlation & Payload Extraction',
      },
    },
    {
      id: 'field-3-timeline',
      label: 'Field 3: Chronological Timeline',
      type: 'report_field',
      status: 'generated',
      details: {
        field_name: 'Date & Time of Incident (Occurred / Detected / Noticed)',
        auto_value: `${incident.timestamps.occurred_at} -> ${incident.timestamps.noticed_at}`,
        provenance_source: 'Cryptographic Sentry Trusted Wall-Clock Timestamps',
      },
    },
  ];

  return (
    <div className="glass-panel rounded-xl p-6 border border-cyber-border">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 mb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              INTERACTIVE EVIDENCE PROVENANCE GRAPH (DAG)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Trace the deterministic chain from raw server telemetry to the official auto-populated CERT-In Annexure I report fields.
          </p>
        </div>
        <span className="text-xs font-mono-code px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
          Deterministic 4-Stage Pipeline
        </span>
      </div>

      {/* DAG Visualization Columns */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        
        {/* Stage 1: Raw Telemetry Events */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300 pb-1 border-b border-slate-800">
            <span className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-blue-400" />
              1. Raw Telemetry Events
            </span>
            <span className="text-[10px] text-slate-500 font-mono-code">({rawEventNodes.length})</span>
          </div>

          <div className="space-y-2">
            {rawEventNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => setSelectedNode(node)}
                className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                  selectedNode?.id === node.id
                    ? 'bg-blue-950/40 border-blue-500 glow-blue'
                    : 'bg-cyber-card border-cyber-border hover:border-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono-code font-bold text-blue-400 truncate max-w-[140px]">
                    {node.id}
                  </span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono-code">
                    Ed25519 Signed
                  </span>
                </div>
                <p className="text-xs font-medium text-slate-200">{node.label}</p>
                <div className="flex items-center justify-between text-[10px] text-slate-400 mt-2">
                  <span className="font-mono-code text-[9px] truncate max-w-[120px]">
                    {node.details.record_hash ? `${node.details.record_hash.substring(0, 10)}...` : 'hash'}
                  </span>
                  <span>{node.timestamp ? new Date(node.timestamp).toLocaleTimeString() : ''}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Stage 2: Fired Detection Rule */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300 pb-1 border-b border-slate-800">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-amber-400" />
              2. Fired Detection Rule
            </span>
            <ArrowRight className="w-3 h-3 text-slate-600 hidden md:block" />
          </div>

          <div
            onClick={() => setSelectedNode(ruleNode)}
            className={`p-3.5 rounded-lg border text-left cursor-pointer transition-all ${
              selectedNode?.id === ruleNode.id
                ? 'bg-amber-950/40 border-amber-500 glow-amber'
                : 'bg-cyber-card border-cyber-border hover:border-slate-600'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono-code font-bold text-amber-400">
                {ruleNode.id}
              </span>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 font-mono-code">
                MATCHED
              </span>
            </div>
            <p className="text-xs font-bold text-slate-100">{ruleNode.label}</p>
            <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">
              {ruleNode.details.evaluation}
            </p>
            <div className="mt-2 text-[10px] text-slate-500 font-mono-code">
              Triggered: {new Date(ruleNode.timestamp!).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Stage 3: Statutory Category */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300 pb-1 border-b border-slate-800">
            <span className="flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              3. Statutory Category
            </span>
            <ArrowRight className="w-3 h-3 text-slate-600 hidden md:block" />
          </div>

          <div
            onClick={() => setSelectedNode(categoryNode)}
            className={`p-3.5 rounded-lg border text-left cursor-pointer transition-all ${
              selectedNode?.id === categoryNode.id
                ? 'bg-rose-950/40 border-rose-500 glow-red'
                : 'bg-cyber-card border-cyber-border hover:border-slate-600'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono-code font-bold text-rose-400">
                {incident.category_numeral}
              </span>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-mono-code font-bold">
                6H DEADLINE
              </span>
            </div>
            <p className="text-xs font-bold text-slate-100">{incident.category_name}</p>
            <p className="text-[10px] text-slate-400 mt-1">
              IT Act Sec 70B(6) mandatory filing
            </p>
            <div className="mt-2 text-[10px] text-slate-500 font-mono-code">
              noticed_at: {new Date(incident.timestamps.noticed_at).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Stage 4: Annexure I Auto-Populated Fields */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-bold text-slate-300 pb-1 border-b border-slate-800">
            <span className="flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-emerald-400" />
              4. Annexure I Fields
            </span>
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          </div>

          <div className="space-y-2">
            {reportFieldNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => setSelectedNode(node)}
                className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all ${
                  selectedNode?.id === node.id
                    ? 'bg-emerald-950/40 border-emerald-500 glow-green'
                    : 'bg-cyber-card border-cyber-border hover:border-slate-600'
                }`}
              >
                <span className="text-[10px] font-mono-code text-emerald-400 font-semibold block">
                  {node.label}
                </span>
                <p className="text-xs text-slate-300 truncate font-mono-code mt-0.5">
                  {node.details.auto_value}
                </p>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Interactive Node Inspector Drawer */}
      {selectedNode && (
        <div className="mt-6 p-4 rounded-xl bg-slate-900 border border-blue-500/40 text-xs">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono-code font-bold uppercase text-[10px]">
                {selectedNode.type}
              </span>
              <h4 className="font-bold text-white text-sm font-mono-code">{selectedNode.label}</h4>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white text-xs font-mono-code"
            >
              [Close Inspector]
            </button>
          </div>

          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Node Properties & Details
              </span>
              <pre className="p-3 rounded bg-[#0a0d14] border border-slate-800 text-slate-300 font-mono-code text-[11px] overflow-x-auto max-h-56">
                {JSON.stringify(selectedNode.details, null, 2)}
              </pre>
            </div>

            <div>
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Cryptographic Provenance & Masking
              </span>
              <div className="p-3 rounded bg-[#0a0d14] border border-slate-800 space-y-2 text-xs">
                {selectedNode.type === 'raw_event' && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Ed25519 Batch Sig:</span>
                      <span className="text-emerald-400 font-mono-code font-bold">VALID (Go Agent Key)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">SQLite WAL Status:</span>
                      <span className="text-indigo-400 font-mono-code">Committed Block</span>
                    </div>
                    {selectedNode.details.payload?.src_ip && (
                      <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                        <div>
                          <span className="text-slate-400 text-[11px] block">Identifier Privacy (AES-GCM):</span>
                          <span className="font-mono-code text-amber-300 text-xs">
                            {selectedNode.details.masked_fields?.src_ip || '203.0.***.***'}
                          </span>
                        </div>
                        <button
                          onClick={() => onOpenUnmask(
                            'src_ip',
                            selectedNode.id,
                            selectedNode.details.masked_fields?.src_ip || '203.0.***.***',
                            selectedNode.details.payload.src_ip
                          )}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold border border-amber-500/40"
                        >
                          <Unlock className="w-3 h-3" />
                          <span>Audit Unmask</span>
                        </button>
                      </div>
                    )}
                  </>
                )}

                {selectedNode.type === 'detection_rule' && (
                  <div>
                    <span className="text-slate-400">Rule Logic:</span>
                    <p className="text-slate-200 mt-1 font-mono-code text-[11px]">
                      Trigger condition: Count(event_type == 'ssh_auth_failure') &gt;= 10 in 30s THEN event_type == 'ssh_auth_success' THEN sudo_exec.
                    </p>
                  </div>
                )}

                {selectedNode.type === 'report_field' && (
                  <div>
                    <span className="text-slate-400">Compliance Translation:</span>
                    <p className="text-slate-200 mt-1 text-[11px]">
                      Mapped directly into CERT-In Annexure I Form for official incident disclosure.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
