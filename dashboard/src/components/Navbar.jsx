import React from 'react';
import { Shield, FileText, ArrowUpRight, Cpu, Lock } from 'lucide-react';

export default function Navbar({ onOpenReport }) {
  return (
    <header className="sticky top-0 z-50 pt-4 px-4 sm:px-6">
      <nav className="max-w-7xl mx-auto rounded-full bg-[#080d16]/85 backdrop-blur-2xl border border-white/10 shadow-[0_20px_40px_-15px_rgba(0,0,0,0.8)] px-4 sm:px-6 py-2.5 flex items-center justify-between gap-4 transition-all duration-300">
        
        {/* Brand & Project Identity */}
        <div className="flex items-center gap-3">
          <div className="relative group">
            <div className="w-9 h-9 rounded-full bg-gradient-to-br from-sky-400 to-sky-600 flex items-center justify-center font-bold text-white shadow-lg shadow-sky-500/20 ring-2 ring-white/20 group-hover:scale-105 transition-transform duration-300">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 rounded-full ring-2 ring-[#080d16]" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm tracking-tight text-white font-sans">
                BARBARIKA
              </span>
              <span className="text-[10px] uppercase tracking-widest font-semibold px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/20 font-mono">
                SIH 2026
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans hidden sm:block">
              Assisted 6-Hour CERT-In Incident Reporting Engine • MPSTME, NMIMS
            </p>
          </div>
        </div>

        {/* Center Indicators */}
        <div className="hidden lg:flex items-center gap-3 font-mono text-xs text-slate-400">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.03] border border-white/5">
            <Lock className="w-3 h-3 text-emerald-400" />
            <span>mTLS 1.3 Outbound</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.03] border border-white/5">
            <Cpu className="w-3 h-3 text-sky-400" />
            <span>Go &lt;15MB RAM</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.03] border border-white/5 text-amber-300 font-semibold">
            <span>IT Act Sec 70B</span>
          </div>
        </div>

        {/* Right CTA: Button-in-Button Architecture */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenReport}
            className="group relative flex items-center gap-3 pl-4 pr-1.5 py-1.5 rounded-full bg-gradient-to-r from-sky-500 to-sky-600 hover:from-sky-400 hover:to-sky-500 text-white text-xs font-semibold font-sans tracking-tight shadow-lg shadow-sky-500/25 transition-all duration-300 hover:shadow-sky-500/40 active:scale-[0.98] cursor-pointer"
          >
            <span>Annexure I Packet</span>
            <div className="w-7 h-7 rounded-full bg-white/20 group-hover:bg-white/30 flex items-center justify-center transition-all duration-300 group-hover:scale-110 group-hover:rotate-12">
              <ArrowUpRight className="w-3.5 h-3.5 text-white" />
            </div>
          </button>
        </div>

      </nav>
    </header>
  );
}
