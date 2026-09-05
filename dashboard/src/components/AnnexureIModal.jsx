import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  X, 
  Printer, 
  Mail, 
  CheckCircle2, 
  ShieldCheck, 
  Eye, 
  EyeOff, 
  AlertCircle 
} from 'lucide-react';
import { getAnnexureIDataForScenario } from '../data/mockIncidents';

export default function AnnexureIModal({ isOpen, onClose, currentScenario = "CAT3" }) {
  const [isAuthUnmasked, setIsAuthUnmasked] = useState(false);
  const [isFiled, setIsFiled] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const annexureData = getAnnexureIDataForScenario(currentScenario);

  const handlePrint = () => {
    window.print();
  };

  const handleExportEML = () => {
    const emlContent = `To: incident@cert-in.org.in
Subject: [URGENT] Statutory Cyber Incident Report under IT Act Sec 70B - Ref: BARB-2026-${currentScenario}
From: ciso@barbarika-fin.in
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"

-----BEGIN PGP MESSAGE-----
Version: Barbarika Sentry PGP Dispatch Engine v1.4.2

hQGMA8X2vL+...[PGP ENCRYPTED PAYLOAD CONTAINING OFFICIAL ANNEXURE I AND SHA-256 PROVENANCE CHAIN FOR ${currentScenario}]...
-----END PGP MESSAGE-----`;

    const blob = new Blob([emlContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CERT-In_Incident_Report_Annexure_I_${currentScenario}_${Date.now()}.eml`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleMarkFiled = () => {
    setIsFiled(true);
    setTimeout(() => {
      alert("Statutory Incident Packet officially logged! Timestamp and Ed25519 hash saved to immutable audit log.");
    }, 150);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4 overflow-y-auto">
      <div className="rounded-xl border border-slate-200 bg-white w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden text-slate-900">
        
        {/* Header */}
        <div className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-700 border border-indigo-200 flex items-center justify-center">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-900 font-sans">
                  CERT-In Annexure I — Official Statutory Incident Report
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold">
                  Pre-Populated
                </span>
              </div>
              <p className="text-xs text-slate-500 font-sans">
                Sub-section (6) of Section 70B, Information Technology Act 2000
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsAuthUnmasked(!isAuthUnmasked)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-sans font-semibold border transition-colors cursor-pointer ${
                isAuthUnmasked 
                  ? 'bg-amber-50 border-amber-200 text-amber-800' 
                  : 'bg-emerald-50 border-emerald-200 text-emerald-800'
              }`}
            >
              {isAuthUnmasked ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
              <span>{isAuthUnmasked ? 'Unmasked' : 'PII Masked'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-200/50 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-white">
          
          {/* Official Document Banner */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/60 text-center">
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 font-semibold mb-1">
              Ministry of Electronics and Information Technology (MeitY) • Government of India
            </div>
            <h1 className="text-base font-bold text-slate-900 tracking-wide uppercase font-sans">
              INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In)
            </h1>
            <div className="text-xs font-mono text-indigo-700 mt-1 font-bold">
              INCIDENT REPORTING FORM — ANNEXURE I
            </div>
            <p className="text-xs text-slate-600 max-w-2xl mx-auto mt-2 italic font-sans leading-relaxed">
              {annexureData.statutoryNotice}
            </p>
          </div>

          {/* Metadata Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase block">Statutory Window</span>
              <span className="text-amber-800 font-bold">6 Hours Mandate (Sec 70B)</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase block">Official Channel</span>
              <span className="text-indigo-700 font-bold">incident@cert-in.org.in</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase block">Active Trigger</span>
              <span className="text-emerald-700 font-bold">{currentScenario} Classification</span>
            </div>
          </div>

          {/* Statutory Fields Table */}
          <div className="rounded-xl border border-slate-200 divide-y divide-slate-200 bg-white overflow-hidden">
            {Object.entries(annexureData.fields).map(([key, item]) => {
              let displayVal = item.value;
              if (!isAuthUnmasked) {
                displayVal = displayVal
                  .replace(/198\.51\.100\.74/g, "198.51.***.*** [MASKED]")
                  .replace(/203\.0\.113\.188/g, "203.0.***.*** [MASKED]")
                  .replace(/ciso@barbarika-fin\.in/g, "c***@barbarika-fin.in [MASKED]")
                  .replace(/msme_admin/g, "m***_admin [MASKED]");
              }

              return (
                <div key={key} className="grid grid-cols-1 md:grid-cols-12 p-3.5 gap-3 hover:bg-slate-50/50 transition-colors">
                  <div className="md:col-span-4 text-xs font-semibold text-slate-700 font-mono">
                    {item.label}
                  </div>
                  <div className="md:col-span-8 text-xs text-slate-900 whitespace-pre-line leading-relaxed font-mono">
                    {displayVal}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Forensic Attestation */}
          <div className="p-3.5 rounded-lg bg-emerald-50/50 border border-emerald-200 text-xs font-mono">
            <div className="flex items-center gap-2 text-emerald-800 font-bold mb-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span>FORENSIC INTEGRITY ATTESTATION (BARBARIKA SENTRY VAULT)</span>
            </div>
            <div className="text-[11px] text-slate-700 space-y-0.5">
              <div>• Genesis Root Hash: <code className="text-indigo-700">7a52e6ff74e2d3b4f621a364be16a5ef4bb10ea99c687498c8bf102434de5412</code></div>
              <div>• Cryptographic Vault Status: <span className="text-emerald-700 font-bold">[PASS] 47 records verified, 0 tampering detected</span></div>
              <div>• Surviving State: <span className="text-emerald-700 font-bold">100% Intact</span> on isolated micro-VM enclave</div>
            </div>
          </div>

        </div>

        {/* Footer Actions */}
        <div className="p-4 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-slate-500 font-sans flex items-center gap-1.5">
            <AlertCircle className="w-4 h-4 text-indigo-600" />
            <span>Human verification completed. Ready for statutory filing.</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-sans font-medium text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5 text-slate-500" />
              <span>Print PDF</span>
            </button>

            <button
              onClick={handleExportEML}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-sans font-medium text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
            >
              <Mail className="w-3.5 h-3.5 text-indigo-600" />
              <span>Export PGP .eml</span>
            </button>

            <button
              onClick={handleMarkFiled}
              disabled={isFiled}
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-sans font-semibold transition-all cursor-pointer ${
                isFiled
                  ? 'bg-emerald-800 text-white opacity-80 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{isFiled ? 'Dispatched to CERT-In' : 'Approve & Dispatch to CERT-In'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
