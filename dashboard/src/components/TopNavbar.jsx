import React, { useState } from 'react';
import { Shield, FileText, Loader2 } from 'lucide-react';

// Ask the compliance service to fill the official CERT-In Incident Reporting Form
// for the given incident (or the latest) and stream it back as a downloaded PDF.
async function downloadReport(incidentUuid) {
  const q = incidentUuid ? `?incident=${encodeURIComponent(incidentUuid)}` : '?incident=latest';
  const res = await fetch(`/api/compliance/report${q}`);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    throw new Error(detail);
  }
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') || '';
  const m = cd.match(/filename="?([^";]+)"?/);
  const name = m ? m[1] : 'CERT-In_Incident_Report.pdf';
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}

export default function TopNavbar({ latestIncidentId }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const onClick = async () => {
    setBusy(true); setErr('');
    try {
      await downloadReport(latestIncidentId);
    } catch (e) {
      setErr(e.message || 'report failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <header className="border-b border-slate-200/90 bg-white/95 backdrop-blur-md px-4 py-2.5 shrink-0 z-30 shadow-xs text-slate-800">
      <div className="flex items-center justify-between gap-3">
        
        {/* Brand (Kept) */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-600 to-indigo-800 text-white flex items-center justify-center font-bold shadow-xs">
              <Shield className="w-4 h-4 text-white" />
            </div>
          </div>

          <div>
            <h1 className="text-base font-bold text-slate-900 tracking-wider uppercase font-sans">
              BARBARIKA
            </h1>
          </div>
        </div>

        {/* Right Action Controls: Clean and Minimal */}
        <div className="flex items-center gap-2.5 shrink-0">
          {err && <span className="text-[11px] text-red-600 font-mono max-w-[240px] truncate" title={err}>{err}</span>}
          <button
            onClick={onClick}
            disabled={busy}
            title="Fill and download the official CERT-In Incident Reporting Form for the latest incident"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-sans font-semibold bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white shadow-xs transition-all cursor-pointer"
          >
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileText className="w-3.5 h-3.5 text-indigo-100" />}
            <span>{busy ? 'Generating…' : 'Incident Report'}</span>
          </button>
        </div>

      </div>
    </header>
  );
}

