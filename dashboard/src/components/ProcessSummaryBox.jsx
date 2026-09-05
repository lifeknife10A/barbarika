import React from 'react';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  Flame, 
  HardDrive, 
  Lock,
  ArrowRight
} from 'lucide-react';

export default function ProcessSummaryBox({ 
  currentStep = 1, 
  primaryState = "HEALTHY", 
  watchdogState = "WATCHING",
  scenario = "CAT3",
  scenarioData
}) {
  // Compute real-time process narrative based on the active step and state
  const getProcessDetails = () => {
    switch (currentStep) {
      case 1:
        return {
          title: "System Nominal • Continuous Telemetry Ingestion",
          statusColor: "text-emerald-400",
          statusBadge: "HEALTHY",
          badgeBg: "bg-emerald-950/50 text-emerald-300 border-emerald-800/60",
          summary: "Primary host (prod-fin-vps01) is running the Go daemon (<15MB RAM). Outbound-only mTLS 1.3 telemetry is active with zero open inbound ports. Isolated Black-Box Sentry is armed with 5-second sliding heartbeat watchdog. 47 historical records verified.",
          nextAction: "Continuously tailing /var/log/auth.log and nginx access logs via fsnotify."
        };
      case 2:
        return {
          title: "Intrusion Tripped • Deterministic Rule Matched",
          statusColor: "text-amber-400",
          statusBadge: "THREAT DETECTED",
          badgeBg: "bg-amber-950/50 text-amber-300 border-amber-800/60",
          summary: `Attacker initiated high-frequency attack vectors. Deterministic Sigma correlation matched ${scenarioData?.ruleId || 'SIGMA-CAT3-001'}. Incident automatically classified under ${scenarioData?.category || 'Category III'} (${scenarioData?.categoryTitle || 'Unauthorized Access'}). Statutory 6-hour Section 70B reporting clock has begun.`,
          nextAction: "Compiling raw cryptographic event logs into Annexure I draft."
        };
      case 3:
        return {
          title: "Adversarial Host Annihilation • Dead-Man's Switch Fired",
          statusColor: "text-rose-400",
          statusBadge: "SUSPECTED COMPROMISE",
          badgeBg: "bg-rose-950/50 text-rose-300 border-rose-800/60",
          summary: "Attacker executed SIGKILL (kill -9) on the primary host daemon to scrub logs. Sentry Inverted Watchdog detected 3 consecutive missed pings (15s sliding window) following the intrusion, immediately escalating to SUSPECTED_COMPROMISE. Evidence in Sentry Vault remains 100% intact.",
          nextAction: "Primary host quarantined; Sentry Vault locked in read-only forensic mode."
        };
      case 4:
        return {
          title: "Cryptographic Vault Audit • Zero Tampering Detected",
          statusColor: "text-sky-400",
          statusBadge: "INTEGRITY VERIFIED",
          badgeBg: "bg-sky-950/50 text-sky-300 border-sky-800/60",
          summary: "Cryptographic SHA-256 recursive chain verification executed across all SQLite WAL segments. Genesis anchor verified. 47 records validated in 42ms with zero tampering detected, proving evidence survived primary host annihilation.",
          nextAction: "Ready for statutory attestation and legal officer sign-off."
        };
      case 5:
        return {
          title: "Official Annexure I Prepared • Ready for Statutory Filing",
          statusColor: "text-emerald-400",
          statusBadge: "COMPLIANCE READY",
          badgeBg: "bg-emerald-950/50 text-emerald-300 border-emerald-800/60",
          summary: "All 12 statutory fields for CERT-In Annexure I pre-populated from deterministic rule correlation and cryptographic hashes. Customer PII filtered via Presidio. PGP-encrypted .eml draft ready for transmission to incident@cert-in.org.in.",
          nextAction: "Human reviewer approval required to dispatch statutory notice."
        };
      default:
        return {
          title: "Active Process Telemetry",
          statusColor: "text-slate-300",
          statusBadge: "STANDBY",
          badgeBg: "bg-slate-800 text-slate-300 border-slate-700",
          summary: "Monitoring active telemetry stream.",
          nextAction: "Standing by."
        };
    }
  };

  const processInfo = getProcessDetails();

  return (
    <div className="rounded-lg border border-slate-800 bg-[#090d16] p-3.5 flex flex-col justify-between">
      <div>
        {/* Header */}
        <div className="flex items-center justify-between pb-2 border-b border-slate-800/80 mb-2.5">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              Live Process & Incident Summary
            </h3>
          </div>
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${processInfo.badgeBg}`}>
            {processInfo.statusBadge}
          </span>
        </div>

        {/* Process Title */}
        <h4 className={`text-xs font-semibold font-sans mb-1.5 ${processInfo.statusColor}`}>
          {processInfo.title}
        </h4>

        {/* Plain English Summary */}
        <p className="text-xs text-slate-300 font-sans leading-relaxed">
          {processInfo.summary}
        </p>
      </div>

      {/* Process Meta Footer */}
      <div className="mt-3 pt-2.5 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
        <div className="bg-[#06090f] p-1.5 rounded border border-slate-800/60">
          <span className="text-slate-500 uppercase block">Active Trigger:</span>
          <span className="text-slate-200 font-semibold">{scenarioData?.category || 'Category III'}</span>
        </div>
        <div className="bg-[#06090f] p-1.5 rounded border border-slate-800/60">
          <span className="text-slate-500 uppercase block">Host State:</span>
          <span className={primaryState === "KILLED" ? "text-rose-400 font-semibold" : "text-emerald-400"}>
            {primaryState === "KILLED" ? "FLATLINED" : "AGENT RUNNING"}
          </span>
        </div>
        <div className="bg-[#06090f] p-1.5 rounded border border-slate-800/60">
          <span className="text-slate-500 uppercase block">Sentry Vault:</span>
          <span className="text-emerald-400 font-semibold">47 Records Intact</span>
        </div>
        <div className="bg-[#06090f] p-1.5 rounded border border-slate-800/60">
          <span className="text-slate-500 uppercase block">Next Action:</span>
          <span className="text-sky-300 truncate block">{processInfo.nextAction}</span>
        </div>
      </div>
    </div>
  );
}
