import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Clock, 
  FileText, 
  ArrowUpRight, 
  Eye, 
  EyeOff, 
  Scale,
  Server,
  Layers
} from 'lucide-react';

export default function Header({ 
  isSlaActive, 
  timeRemainingSeconds = 21540,
  currentScenario,
  onSelectScenario,
  isPiiMasked,
  onToggleMask,
  onOpenReport 
}) {
  const [secondsLeft, setSecondsLeft] = useState(timeRemainingSeconds);

  useEffect(() => {
    if (!isSlaActive) return;
    const interval = setInterval(() => {
      setSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, [isSlaActive]);

  const hours = Math.floor(secondsLeft / 3600);
  const minutes = Math.floor((secondsLeft % 3600) / 60);
  const seconds = secondsLeft % 60;
  const format2Digits = (num) => String(num).padStart(2, '0');

  return (
    <header className="border-b border-white/[0.08] bg-[#070b13] sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        
        {/* Left: Brand Identity & Target System */}
        <div className="flex items-center gap-3.5">
          <div className="w-9 h-9 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20 flex items-center justify-center font-bold">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold text-white tracking-tight font-sans">
                BARBARIKA
              </h1>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-white/[0.04] text-slate-400 border border-white/5 font-semibold">
                CERT-In 6H Engine
              </span>
              <span className="text-xs text-slate-500 hidden md:inline">
                • prod-fin-vps01
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans">
              MPSTME NMIMS • Lead: Nandini Chitlangia
            </p>
          </div>
        </div>

        {/* Center: Clean 6-Hour Statutory SLA Clock */}
        <div className="flex items-center gap-3 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 font-mono">
          <div className="flex items-center gap-1.5 text-xs">
            <span className={`w-2 h-2 rounded-full ${
              isSlaActive ? 'bg-amber-400 animate-ping' : 'bg-emerald-400'
            }`} />
            <span className="text-slate-400 uppercase text-[11px]">
              {isSlaActive ? 'Sec 70B Clock:' : 'SLA Standby:'}
            </span>
          </div>

          <div className={`text-sm font-bold tracking-wider px-2 py-0.5 rounded ${
            isSlaActive 
              ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20' 
              : 'text-slate-300'
          }`}>
            {isSlaActive ? (
              <span>{format2Digits(hours)}:{format2Digits(minutes)}:{format2Digits(seconds)}</span>
            ) : (
              <span>06:00:00</span>
            )}
          </div>

          <div className="hidden lg:block text-[10px] text-slate-500 border-l border-white/5 pl-2">
            Max ₹1 Cr Penalty
          </div>
        </div>

        {/* Right: Scenario Selector, Presidio Toggle, & Primary Action */}
        <div className="flex items-center gap-2.5">
          {/* Path / Scenario Switcher */}
          <div className="hidden sm:flex items-center gap-1 bg-white/[0.03] border border-white/5 rounded-lg p-0.5 text-xs font-mono">
            <button
              onClick={() => onSelectScenario('CAT3')}
              className={`px-2.5 py-1 rounded transition-colors ${
                currentScenario === 'CAT3'
                  ? 'bg-sky-500/20 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Cat III
            </button>
            <button
              onClick={() => onSelectScenario('CAT10')}
              className={`px-2.5 py-1 rounded transition-colors ${
                currentScenario === 'CAT10'
                  ? 'bg-sky-500/20 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Cat X
            </button>
            <button
              onClick={() => onSelectScenario('CAT5')}
              className={`px-2.5 py-1 rounded transition-colors ${
                currentScenario === 'CAT5'
                  ? 'bg-sky-500/20 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Cat V
            </button>
          </div>

          {/* Presidio PII Masking Toggle */}
          <button
            onClick={onToggleMask}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-colors cursor-pointer ${
              isPiiMasked 
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20' 
                : 'bg-amber-500/10 border-amber-500/20 text-amber-300 hover:bg-amber-500/20'
            }`}
            title="Presidio PII Redaction"
          >
            {isPiiMasked ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            <span className="hidden md:inline">{isPiiMasked ? 'PII Masked' : 'Raw Data'}</span>
          </button>

          {/* Primary Action Button */}
          <button
            onClick={onOpenReport}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold font-sans tracking-tight transition-all shadow-sm active:scale-[0.98] cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Annexure I Packet</span>
          </button>
        </div>

      </div>
    </header>
  );
}
