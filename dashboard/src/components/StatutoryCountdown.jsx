import React, { useState, useEffect } from 'react';
import { Clock, ShieldAlert, ArrowUpRight, AlertCircle, Scale } from 'lucide-react';

export default function StatutoryCountdown({ 
  isActive, 
  onOpenReport, 
  category = "Category III",
  timeRemainingSeconds = 21540
}) {
  const [secondsLeft, setSecondsLeft] = useState(timeRemainingSeconds);

  useEffect(() => {
    if (!isActive) return;
    const interval = setInterval(() => {
      setSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, [isActive]);

  const hours = Math.floor(secondsLeft / 3600);
  const minutes = Math.floor((secondsLeft % 3600) / 60);
  const seconds = secondsLeft % 60;

  const format2Digits = (num) => String(num).padStart(2, '0');

  const isCritical = secondsLeft < 3600;
  const isWarning = secondsLeft < 7200;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6">
      {/* Double-Bezel Enclosure */}
      <div className={`p-1.5 rounded-3xl transition-all duration-500 ease-[cubic-bezier(0.32,0.72,0,1)] ${
        !isActive 
          ? 'bg-white/[0.02] ring-1 ring-white/10 shadow-2xl' 
          : isCritical
          ? 'bg-rose-500/10 ring-1 ring-rose-500/30 shadow-[0_0_40px_rgba(244,63,94,0.15)]'
          : isWarning
          ? 'bg-amber-500/10 ring-1 ring-amber-500/30 shadow-[0_0_40px_rgba(245,158,11,0.15)]'
          : 'bg-sky-500/10 ring-1 ring-sky-500/30 shadow-[0_0_40px_rgba(14,165,233,0.15)]'
      }`}>
        <div className="rounded-[calc(1.5rem-0.375rem)] bg-[#070b13] border border-white/5 p-4 sm:p-5 shadow-[inset_0_1px_1px_rgba(255,255,255,0.08)] flex flex-wrap items-center justify-between gap-4">
          
          {/* Left: Statutory Compliance Status */}
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-all duration-300 ${
              !isActive 
                ? 'bg-white/[0.04] text-slate-400 ring-1 ring-white/10' 
                : isCritical
                ? 'bg-rose-500/20 text-rose-400 ring-1 ring-rose-500/40 animate-pulse'
                : 'bg-amber-500/20 text-amber-400 ring-1 ring-amber-500/40'
            }`}>
              <ShieldAlert className="w-6 h-6" />
            </div>

            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] uppercase font-mono tracking-widest font-semibold border ${
                  isActive 
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' 
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'}`} />
                  {isActive ? 'STATUTORY CLOCK RUNNING' : 'STANDBY MONITORING'}
                </span>
                <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
                  IT Act Sec 70B(6)
                </span>
              </div>

              <h2 className="text-base font-bold text-white tracking-tight font-sans">
                {isActive ? (
                  <span className="text-white">
                    Mandatory 6-Hour Window Active: <span className="text-amber-400 font-semibold">{category}</span>
                  </span>
                ) : (
                  <span className="text-slate-300 font-normal">
                    Statutory Breach Reporting SLA: <strong className="text-white font-semibold">Ready to Assist</strong>
                  </span>
                )}
              </h2>
            </div>
          </div>

          {/* Center: OLED Digital Countdown */}
          <div className="flex items-center gap-4">
            <div className="flex flex-col text-right hidden sm:flex font-mono">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider">Filing Deadline</span>
              <span className="text-xs text-slate-300 font-semibold">IST Mandate</span>
            </div>

            <div className={`px-4 py-2 rounded-2xl font-mono text-2xl sm:text-3xl font-bold tracking-widest border transition-all duration-300 ${
              !isActive 
                ? 'bg-white/[0.02] border-white/10 text-slate-500' 
                : isCritical
                ? 'bg-rose-950/40 border-rose-500/50 text-rose-200 shadow-[0_0_25px_rgba(244,63,94,0.3)] animate-pulse'
                : 'bg-sky-950/30 border-sky-500/40 text-sky-300 shadow-[0_0_20px_rgba(14,165,233,0.2)]'
            }`}>
              {isActive ? (
                <>
                  <span>{format2Digits(hours)}</span>
                  <span className="animate-pulse text-sky-400/60">:</span>
                  <span>{format2Digits(minutes)}</span>
                  <span className="animate-pulse text-sky-400/60">:</span>
                  <span>{format2Digits(seconds)}</span>
                </>
              ) : (
                <span>06:00:00</span>
              )}
            </div>

            {/* Statutory Penalty Card */}
            <div className="hidden lg:flex items-center gap-2.5 px-3 py-2 rounded-xl bg-white/[0.02] border border-white/5 font-mono text-xs text-slate-400">
              <Scale className="w-4 h-4 text-rose-400 shrink-0" />
              <div className="text-[11px] leading-tight">
                <span className="text-rose-400 font-bold block">SEC 70B(7) LIABILITY</span>
                <span>Up to ₹1 Cr Fine + 1 Yr Jail</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
