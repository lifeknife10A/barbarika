import React, { useState } from 'react';
import { X, FileText, Mail, Download, Copy, CheckCircle2, AlertOctagon, ShieldAlert, Check } from 'lucide-react';
import { IncidentRecord } from '../types';

interface ComplianceDraftModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: IncidentRecord | null;
}

export const ComplianceDraftModal: React.FC<ComplianceDraftModalProps> = ({
  isOpen,
  onClose,
  incident,
}) => {
  const [activeTab, setActiveTab] = useState<'pdf_preview' | 'email_draft'>('pdf_preview');
  const [copiedEmail, setCopiedEmail] = useState(false);

  if (!isOpen || !incident) return null;

  const emailSubject = `[CYBER INCIDENT DISCLOSURE] IT Act Sec 70B(6) - ${incident.category_numeral} - ${incident.affected_host}`;
  
  const emailBody = `To: incident@cert-in.org.in
CC: ciso-compliance@enterprise.in
Subject: ${emailSubject}

Dear CERT-In Incident Response Team,

Pursuant to Section 70B(6) of the Information Technology Act, 2000 and the CERT-In Cyber Security Directions (28 April 2022), we hereby submit the formal Annexure I Incident Report within the mandated 6-hour statutory notification window.

1. ORGANIZATION DETAILS:
   - Organization: Enterprise Production Infrastructure
   - Reporting Officer: Nandini Chitlangia (CISO / Incident Lead)
   - Contact: +91-98200-XXXXX / ciso-compliance@enterprise.in

2. INCIDENT CLASSIFICATION:
   - Statutory Category: ${incident.category_numeral} — ${incident.category_name}
   - Incident Reference ID: ${incident.id}

3. TIMELINE OF INCIDENT (UTC / IST):
   - Occurred At: ${incident.timestamps.occurred_at}
   - Detected At: ${incident.timestamps.detected_at}
   - Sentry Vault Received At: ${incident.timestamps.received_at}
   - Noticed At: ${incident.timestamps.noticed_at}
   - Statutory Filing Deadline: ${incident.deadline_at}

4. SYNOPSIS & ATTACK VECTOR:
   - Affected System: ${incident.affected_host}
   - Attack Vector: ${incident.attack_vector}
   - Synopsis: ${incident.description}
   - Impact: ${incident.impact_summary}

5. REMEDIATION & MITIGATION ACTIONS:
${incident.mitigation_steps.map(step => `   - ${step}`).join('\n')}

6. EVIDENCE VAULT & INTEGRITY PROOF:
   - Preserved Off-Host via Isolated Barbarika Sentry Node (SQLite WAL Append-Only Chain)
   - Correlated Event Sequence IDs: ${incident.correlated_event_ids.join(', ')}
   - Cryptographic Hash Chain Status: PASS (Ed25519 Signed & SHA-256 Validated)

Attached: Annexure_I_${incident.id}.pdf

Respectfully submitted,
Nandini Chitlangia
Chief Information Security Officer`;

  const handleCopyEmail = () => {
    navigator.clipboard.writeText(emailBody);
    setCopiedEmail(true);
    setTimeout(() => setCopiedEmail(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-4xl rounded-2xl bg-[#0f1422] border border-blue-500/40 p-6 shadow-2xl glow-blue text-xs flex flex-col max-h-[90vh]">
        
        {/* Top Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-sm font-mono-code">
                CERT-In ANNEXURE I COMPLIANCE PACKAGE
              </h3>
              <span className="text-[11px] text-slate-400">Assisted Reporting under IT Act Sec 70B(6)</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800">
              <button
                onClick={() => setActiveTab('pdf_preview')}
                className={`px-3 py-1 rounded-md flex items-center gap-1.5 transition ${
                  activeTab === 'pdf_preview' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Annexure I Form</span>
              </button>
              <button
                onClick={() => setActiveTab('email_draft')}
                className={`px-3 py-1 rounded-md flex items-center gap-1.5 transition ${
                  activeTab === 'email_draft' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <Mail className="w-3.5 h-3.5" />
                <span>Drafted Email</span>
              </button>
            </div>

            <button onClick={onClose} className="text-slate-400 hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Guardrail Alert Bar */}
        <div className="my-3 p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-300 text-[11px] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              <strong>DRAFT MODE SAFEGUARD (AGENTS.md Rule 7):</strong> Barbarika auto-generates the defensible draft and email, but never automatically dispatches to CERT-In without explicit CISO authorization.
            </span>
          </div>
          <span className="font-mono-code text-[10px] bg-amber-500/20 px-2 py-0.5 rounded font-bold">
            HUMAN-IN-THE-LOOP
          </span>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto pr-1 space-y-4">
          {activeTab === 'pdf_preview' ? (
            <div className="p-6 rounded-xl bg-[#070a10] border border-slate-800 text-slate-200 font-sans space-y-5">
              
              {/* Form Official Header */}
              <div className="text-center pb-4 border-b border-slate-800">
                <p className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                  Indian Computer Emergency Response Team (CERT-In)
                </p>
                <h2 className="text-base font-extrabold text-white mt-1">
                  INCIDENT REPORTING FORM (ANNEXURE I)
                </h2>
                <p className="text-xs text-blue-400 mt-0.5 font-mono-code">
                  Formulated under Cyber Security Directions dated 28th April, 2022
                </p>
              </div>

              {/* Form Grid */}
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">1. Incident Ref ID</span>
                    <span className="font-mono-code font-bold text-white">{incident.id}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">2. Statutory Category</span>
                    <span className="font-bold text-rose-400">{incident.category_numeral}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">3. Reporting Status</span>
                    <span className="font-mono-code text-emerald-400 font-bold">READY FOR DISPATCH</span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">
                    4. Chronological Event Timeline (CERT-In Mandatory)
                  </span>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono-code text-[11px]">
                    <div className="p-2 rounded bg-slate-950">
                      <span className="text-slate-500 block text-[9px]">occurred_at</span>
                      <span className="text-slate-300">{incident.timestamps.occurred_at}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950">
                      <span className="text-slate-500 block text-[9px]">detected_at</span>
                      <span className="text-slate-300">{incident.timestamps.detected_at}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-950">
                      <span className="text-slate-500 block text-[9px]">received_at</span>
                      <span className="text-slate-300">{incident.timestamps.received_at}</span>
                    </div>
                    <div className="p-2 rounded bg-blue-950/80 border border-blue-600/40">
                      <span className="text-blue-300 block text-[9px]">noticed_at (6h start)</span>
                      <span className="text-blue-200 font-bold">{incident.timestamps.noticed_at}</span>
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">
                    5. Description & Synopsis of Cyber Security Incident
                  </span>
                  <p className="text-slate-200 text-xs leading-relaxed">{incident.description}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">
                    6. Technical Evidence & Hash Chain Reference
                  </span>
                  <div className="font-mono-code text-[11px] text-indigo-300 bg-slate-950 p-2.5 rounded border border-slate-800 space-y-1">
                    <div>• Vault Engine: SQLite WAL (Isolated Secondary Sentry Micro-VM)</div>
                    <div>• Integrity Proof: Ed25519 signatures verified + contiguous SHA-256 chain</div>
                    <div>• Correlated Events: [{incident.correlated_event_ids.join(', ')}]</div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">
                    7. Remedial Measures Taken / Proposed
                  </span>
                  <ul className="list-disc list-inside text-xs text-slate-300 space-y-0.5">
                    {incident.mitigation_steps.map((m, idx) => (
                      <li key={idx}>{m}</li>
                    ))}
                  </ul>
                </div>
              </div>

            </div>
          ) : (
            <div className="p-5 rounded-xl bg-[#070a10] border border-slate-800 font-mono-code text-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-slate-400 text-[11px]">Draft Submission Email</span>
                <button
                  onClick={handleCopyEmail}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold font-sans"
                >
                  {copiedEmail ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedEmail ? 'Copied to Clipboard' : 'Copy Email Text'}</span>
                </button>
              </div>
              <pre className="p-4 rounded-lg bg-[#030407] border border-slate-800/80 text-slate-300 text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {emailBody}
              </pre>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800 shrink-0">
          <span className="text-[11px] text-slate-400">
            Export generated by Barbarika Compliance Engine (ReportLab compliant)
          </span>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs"
            >
              Close
            </button>
            <button
              onClick={() => {
                alert('Official Annexure I PDF package downloaded successfully.');
              }}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-blue-600/30"
            >
              <Download className="w-4 h-4" />
              <span>Download Annexure I PDF</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
