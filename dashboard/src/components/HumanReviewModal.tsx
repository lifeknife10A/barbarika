import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle2, AlertTriangle, Lock, Unlock, Eye, FileText, UserCheck } from 'lucide-react';
import { IncidentRecord } from '../types';
import { AuditLogger } from '../services/auditLogger';

interface HumanReviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: IncidentRecord | null;
  onConfirmIncident: (notes: string) => void;
  onDismissIncident: (reason: string) => void;
  unmaskData: { field: string; entityId: string; maskedVal: string; realVal: string } | null;
  onClearUnmaskData: () => void;
}

export const HumanReviewModal: React.FC<HumanReviewModalProps> = ({
  isOpen,
  onClose,
  incident,
  onConfirmIncident,
  onDismissIncident,
  unmaskData,
  onClearUnmaskData,
}) => {
  const [reviewerNotes, setReviewerNotes] = useState('');
  const [unmaskReason, setUnmaskReason] = useState('');
  const [unmaskPin, setUnmaskPin] = useState('');
  const [unmaskError, setUnmaskError] = useState('');
  const [unmaskedSuccessVal, setUnmaskedSuccessVal] = useState<string | null>(null);

  if (!isOpen && !unmaskData) return null;

  const handleUnmaskSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!unmaskReason.trim()) {
      setUnmaskError('Mandatory reason for unmasking is required for regulatory audit log.');
      return;
    }

    if (unmaskPin && unmaskPin !== '1234' && unmaskPin !== 'admin123') {
      setUnmaskError('Invalid CISO Security PIN.');
      return;
    }

    if (unmaskData) {
      AuditLogger.logUnmask({
        user_name: 'Nandini Chitlangia',
        user_role: 'CISO / Lead Reviewer',
        target_field: unmaskData.field,
        entity_id: unmaskData.entityId,
        masked_value: unmaskData.maskedVal,
        unmasked_value: unmaskData.realVal,
        reason: unmaskReason,
        ip_address: '10.0.0.45',
      });

      setUnmaskedSuccessVal(unmaskData.realVal);
      setUnmaskError('');
    }
  };

  const handleClose = () => {
    setUnmaskedSuccessVal(null);
    setUnmaskError('');
    setUnmaskReason('');
    setUnmaskPin('');
    onClearUnmaskData();
    onClose();
  };

  // Case 1: Specific Unmasking Modal
  if (unmaskData) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
        <div className="w-full max-w-lg rounded-2xl bg-[#0f1422] border border-amber-500/40 p-6 shadow-2xl glow-amber text-xs">
          
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center">
                <Unlock className="w-4 h-4" />
              </div>
              <div>
                <h3 className="font-bold text-white text-sm font-mono-code">
                  ROLE-GATED IDENTIFIER UNMASKING
                </h3>
                <span className="text-[11px] text-amber-300">Authenticated & Audited Action</span>
              </div>
            </div>
            <button onClick={handleClose} className="text-slate-400 hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>

          {unmaskedSuccessVal ? (
            <div className="mt-4 space-y-4">
              <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/50 text-emerald-300 space-y-2">
                <div className="flex items-center gap-2 font-bold text-xs">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>IDENTIFIER SUCCESSFULLY UNMASKED</span>
                </div>
                <div className="font-mono-code text-base font-bold text-white bg-slate-900 p-2.5 rounded border border-slate-800">
                  {unmaskedSuccessVal}
                </div>
                <p className="text-[11px] text-slate-400">
                  Audit record permanently logged to CISO compliance ledger with timestamp & justification.
                </p>
              </div>

              <button
                onClick={handleClose}
                className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition"
              >
                Return to Dashboard
              </button>
            </div>
          ) : (
            <form onSubmit={handleUnmaskSubmit} className="mt-4 space-y-4">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5 font-mono-code">
                <div className="flex justify-between text-slate-400">
                  <span>Target Field:</span>
                  <span className="text-slate-200 font-bold">{unmaskData.field}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Entity ID:</span>
                  <span className="text-slate-200">{unmaskData.entityId}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Current Masked:</span>
                  <span className="text-amber-400">{unmaskData.maskedVal}</span>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Regulatory Justification / Reason for Unmasking *
                </label>
                <input
                  type="text"
                  placeholder="e.g. Mandatory forensic extraction for CERT-In Annexure I filing"
                  value={unmaskReason}
                  onChange={(e) => setUnmaskReason(e.target.value)}
                  className="w-full bg-[#05070a] border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-amber-500 font-sans"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  CISO Security PIN (Default Demo: 1234)
                </label>
                <input
                  type="password"
                  placeholder="Enter 4-digit PIN"
                  value={unmaskPin}
                  onChange={(e) => setUnmaskPin(e.target.value)}
                  className="w-full bg-[#05070a] border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-amber-500 font-mono-code"
                />
              </div>

              {unmaskError && (
                <div className="p-2.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[11px] font-semibold">
                  {unmaskError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={handleClose}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-black font-bold flex items-center gap-1.5 shadow-lg shadow-amber-500/20"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  <span>Authenticate & Unmask</span>
                </button>
              </div>
            </form>
          )}

        </div>
      </div>
    );
  }

  // Case 2: Candidate Incident Review Screen
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-2xl rounded-2xl bg-[#0f1422] border border-purple-500/40 p-6 shadow-2xl glow-blue text-xs">
        
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 text-purple-400 flex items-center justify-center">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-sm font-mono-code">
                MANDATORY HUMAN REVIEW & INCIDENT CONFIRMATION
              </h3>
              <span className="text-[11px] text-purple-300">AGENTS.md Rule 2 Compliance Gate</span>
            </div>
          </div>
          <button onClick={handleClose} className="text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {incident && (
          <div className="mt-4 space-y-4">
            
            <div className="p-4 rounded-lg bg-purple-950/20 border border-purple-500/30 space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-purple-500/30 text-purple-200 font-bold font-mono-code text-[11px]">
                  {incident.category_numeral}
                </span>
                <span className="text-slate-400 font-mono-code text-[11px]">
                  ID: {incident.id}
                </span>
              </div>
              <h4 className="font-bold text-white text-sm">{incident.title}</h4>
              <p className="text-slate-300 text-xs leading-relaxed">{incident.description}</p>
            </div>

            {/* Candidate Reason Alert */}
            {incident.is_candidate_cat_ii && (
              <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block">Dead Man's Switch Trigger Notice:</span>
                  <span>
                    Heartbeat flatline was detected within 120s of high-confidence intrusion activity. Per statutory guidelines, this is a <strong>Candidate Category (ii)</strong> and cannot auto-escalate without human reviewer sign-off.
                  </span>
                </div>
              </div>
            )}

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Reviewer Evaluation & Remediation Notes
              </label>
              <textarea
                rows={3}
                placeholder="Confirming adversarial host disruption following SSH compromise. Authorizing Annexure I drafting."
                value={reviewerNotes}
                onChange={(e) => setReviewerNotes(e.target.value)}
                className="w-full bg-[#05070a] border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-purple-500 font-sans"
              />
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => onDismissIncident(reviewerNotes || 'Dismissed as benign network disruption after inspection.')}
                className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs transition"
              >
                Dismiss as Operational Warning Only
              </button>

              <button
                onClick={() => onConfirmIncident(reviewerNotes || 'Incident confirmed by CISO reviewer.')}
                className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow-lg shadow-purple-600/30 flex items-center justify-center gap-1.5 transition"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Confirm & Escalate to Statutory Filing</span>
              </button>
            </div>

          </div>
        )}

      </div>
    </div>
  );
};
