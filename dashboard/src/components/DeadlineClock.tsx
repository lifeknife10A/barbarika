import React, { useState, useEffect } from 'react';
import { Clock, AlertOctagon, Info, ShieldAlert, CheckCircle2, ChevronDown, ChevronUp } from 'lucide-react';
import { IncidentRecord, IncidentTimestamps } from '../types';

interface DeadlineClockProps {
  incident: IncidentRecord | null;
  onOpenDraft: () => void;
  onOpenReview: () => void;
}

export const DeadlineClock: React.FC<DeadlineClockProps> = ({
  incident,
  onOpenDraft,
  onOpenReview,
}) => {
  const [timeLeft, setTimeLeft] = useState<{ hours: number; minutes: number; seconds: number; totalSec: number } | null>(null);
  const [showTimelineModal, setShowTimelineModal] = useState(false);

  useEffect(() => {
    if (!incident || !incident.timestamps.noticed_at) {
      setTimeLeft(null);
      return;
    }

    const calculateTime = () => {
      const noticedTime = new Date(incident.timestamps.noticed_at).getTime();
      const deadlineTime = noticedTime + (6 * 3600 * 1000); // exactly 6 hours
      const now = Date.now();
      const diffMs = deadlineTime - now;

      if (diffMs <= 0) {
        setTimeLeft({ hours: 0, minutes: 0, seconds: 0, totalSec: 0 });
      } else {
        const totalSec = Math.floor(diffMs / 1000);
        const hours = Math.floor(totalSec / 3600);
        const minutes = Math.floor((totalSec % 3600) / 60);
        const seconds = totalSec % 60;
        setTimeLeft({ hours, minutes, seconds, totalSec });
      }
    };

    calculateTime();
    const interval = setInterval(calculateTime, 1000);
    return () => clearInterval(interval);
  }, [incident]);

  if (!incident) {
    return (
      <div className="glass-panel rounded-xl p-5 border border-emerald-500/20 bg-emerald-950/10">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-white text-sm tracking-wide">STATUTORY 6-HOUR REPORTING DEADLINE</h3>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-xs font-mono-code font-semibold">
                  STANDBY
                </span>
              </div>
              <p className="text-xs text-slate-400">
                IT Act Sec 70B(6) Compliance: 0 Active Incidents. All primary nodes within normal operational parameters.
              </p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-xs text-slate-400 block">Maximum Allowed Filing Window</span>
            <span className="font-mono-code text-slate-300 text-sm font-semibold">06:00:00 from noticed_at</span>
          </div>
        </div>
      </div>
    );
  }

  const totalSixHoursSec = 6 * 3600;
  const elapsedSec = timeLeft ? Math.max(0, totalSixHoursSec - timeLeft.totalSec) : 0;
  const percentElapsed = Math.min(100, Math.max(0, (elapsedSec / totalSixHoursSec) * 100));

  const isUrgent = timeLeft ? timeLeft.hours < 3 : false;
  const isCritical = timeLeft ? timeLeft.hours < 1 : false;

  return (
    <div className={`glass-panel-elevated rounded-xl p-5 border transition-all ${
      isCritical ? 'border-rose-500/80 bg-rose-950/20 glow-red' :
      isUrgent ? 'border-amber-500/80 bg-amber-950/20 glow-amber' :
      'border-blue-500/50 bg-blue-950/20 glow-blue'
    }`}>
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        
        {/* Left Info */}
        <div className="flex items-start gap-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${
            isCritical ? 'bg-rose-500/20 text-rose-400 animate-pulse' :
            isUrgent ? 'bg-amber-500/20 text-amber-400' :
            'bg-blue-500/20 text-blue-400'
          }`}>
            <Clock className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono-code font-bold uppercase tracking-wider ${
                isCritical ? 'bg-rose-500 text-white animate-pulse' :
                isUrgent ? 'bg-amber-500 text-black font-extrabold' :
                'bg-blue-600 text-white'
              }`}>
                IT ACT SEC 70B(6) MANDATE
              </span>
              <span className="text-xs font-semibold text-slate-300">
                {incident.category_numeral}: {incident.category_name}
              </span>
              {incident.is_candidate_cat_ii && incident.status === 'pending_review' && (
                <span className="px-2 py-0.5 rounded bg-purple-500/30 text-purple-300 text-xs font-semibold border border-purple-500/40 animate-pulse">
                  Requires Human Confirmation
                </span>
              )}
            </div>

            <p className="text-xs text-slate-300 max-w-2xl">
              {incident.title} — Mandatory CERT-In reporting window is ticking. Under Section 70B(7), failure to report carries penalties up to ₹1 Crore / imprisonment.
            </p>

            {/* Quick Timestamps Toggle */}
            <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-400">
              <button
                onClick={() => setShowTimelineModal(!showTimelineModal)}
                className="flex items-center gap-1 text-blue-400 hover:text-blue-300 underline underline-offset-2 font-medium"
              >
                <span>Audit 6 Statutory Timestamps</span>
                {showTimelineModal ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
              <span>•</span>
              <span>Noticed at: <strong className="font-mono-code text-slate-200">{new Date(incident.timestamps.noticed_at).toLocaleTimeString()}</strong></span>
            </div>
          </div>
        </div>

        {/* Right Countdown & Actions */}
        <div className="flex flex-col sm:flex-row items-end sm:items-center gap-4">
          <div className="text-right">
            <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 block mb-1">
              Time Remaining to File
            </span>
            <div className="font-mono-code text-3xl sm:text-4xl font-extrabold tracking-tight text-white flex items-center gap-1 justify-end">
              {timeLeft ? (
                <>
                  <span className={isCritical ? 'text-rose-400' : isUrgent ? 'text-amber-400' : 'text-blue-400'}>
                    {String(timeLeft.hours).padStart(2, '0')}
                  </span>
                  <span className="text-slate-500">:</span>
                  <span className={isCritical ? 'text-rose-400' : isUrgent ? 'text-amber-400' : 'text-blue-400'}>
                    {String(timeLeft.minutes).padStart(2, '0')}
                  </span>
                  <span className="text-slate-500">:</span>
                  <span className="text-slate-200">
                    {String(timeLeft.seconds).padStart(2, '0')}
                  </span>
                </>
              ) : (
                <span>06:00:00</span>
              )}
            </div>
          </div>

          <div className="flex flex-col gap-2 w-full sm:w-auto">
            {incident.status === 'pending_review' ? (
              <button
                onClick={onOpenReview}
                className="px-4 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow-lg shadow-purple-600/30 flex items-center justify-center gap-2 transition"
              >
                <ShieldAlert className="w-4 h-4" />
                <span>Review & Confirm Incident</span>
              </button>
            ) : (
              <button
                onClick={onOpenDraft}
                className="px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 transition"
              >
                <AlertOctagon className="w-4 h-4" />
                <span>Auto-Draft Annexure I</span>
              </button>
            )}
          </div>

        </div>

      </div>

      {/* Progress bar */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="flex justify-between text-[10px] text-slate-400 font-mono-code mb-1">
          <span>noticed_at (00:00)</span>
          <span>Elapsed: {Math.floor(elapsedSec / 60)}m ({percentElapsed.toFixed(1)}%)</span>
          <span>Statutory Deadline (06:00:00)</span>
        </div>
        <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-1000 ${
              isCritical ? 'bg-rose-500' : isUrgent ? 'bg-amber-500' : 'bg-blue-500'
            }`}
            style={{ width: `${percentElapsed}%` }}
          ></div>
        </div>
      </div>

      {/* 6 Timestamps Drawer */}
      {showTimelineModal && (
        <div className="mt-4 p-4 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
          <div className="flex items-center justify-between mb-3">
            <h4 className="font-bold text-slate-200 flex items-center gap-1.5 font-mono-code">
              <Info className="w-4 h-4 text-blue-400" />
              STATUTORY TIMESTAMPS BREAKDOWN (AGENTS.md Rule 6)
            </h4>
            <span className="text-[11px] text-slate-400">Strictly non-generic timeline tracking</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono-code">
            <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700/60">
              <span className="text-slate-400 text-[10px] block font-sans font-semibold">1. occurred_at (Host)</span>
              <span className="text-slate-200 text-xs">{incident.timestamps.occurred_at || 'Pending'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700/60">
              <span className="text-slate-400 text-[10px] block font-sans font-semibold">2. detected_at (Go Agent)</span>
              <span className="text-slate-200 text-xs">{incident.timestamps.detected_at || 'Pending'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700/60">
              <span className="text-slate-400 text-[10px] block font-sans font-semibold">3. received_at (Sentry Vault)</span>
              <span className="text-slate-200 text-xs">{incident.timestamps.received_at || 'Pending'}</span>
            </div>
            <div className="p-2.5 rounded bg-blue-950/60 border border-blue-600/40">
              <span className="text-blue-300 text-[10px] block font-sans font-semibold">4. noticed_at (Clock Start)</span>
              <span className="text-blue-200 text-xs font-bold">{incident.timestamps.noticed_at || 'Pending'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700/60">
              <span className="text-slate-400 text-[10px] block font-sans font-semibold">5. confirmed_at (Human Sign-off)</span>
              <span className="text-slate-200 text-xs">{incident.timestamps.confirmed_at || 'Awaiting Review'}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-800/60 border border-slate-700/60">
              <span className="text-slate-400 text-[10px] block font-sans font-semibold">6. reported_at (Annexure I Export)</span>
              <span className="text-slate-200 text-xs">{incident.timestamps.reported_at || 'Drafting Stage'}</span>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
