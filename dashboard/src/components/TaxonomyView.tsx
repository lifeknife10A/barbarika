import React, { useState } from 'react';
import { CheckCircle2, Shield, Search, Check, AlertTriangle, Layers, Info } from 'lucide-react';
import { STATUTORY_CATEGORIES } from '../data/statutoryCategories';

export const TaxonomyView: React.FC = () => {
  const [filter, setFilter] = useState<'all' | 'live' | 'schema'>('all');
  const [search, setSearch] = useState('');

  const filteredCategories = STATUTORY_CATEGORIES.filter(cat => {
    if (filter === 'live' && !cat.isLiveDetected) return false;
    if (filter === 'schema' && cat.isLiveDetected) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        cat.name.toLowerCase().includes(q) ||
        cat.numeral.toLowerCase().includes(q) ||
        cat.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="glass-panel rounded-xl p-6 border border-cyber-border space-y-6">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            <h3 className="font-bold text-slate-100 text-sm tracking-wide">
              CERT-In STATUTORY INCIDENT TAXONOMY
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Annexure I of Cyber Security Directions dated 28th April, 2022 (IT Act Section 70B).
          </p>
        </div>

        {/* Honest Phrasing Badge */}
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-mono-code font-bold border border-blue-500/30">
            20/20 Schema Model | 3 Live Detectors
          </span>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800 text-xs">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-md transition ${filter === 'all' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            All 20 Categories
          </button>
          <button
            onClick={() => setFilter('live')}
            className={`px-3 py-1 rounded-md transition ${filter === 'live' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            Live Detected (3 + 1 Candidate)
          </button>
          <button
            onClick={() => setFilter('schema')}
            className={`px-3 py-1 rounded-md transition ${filter === 'schema' ? 'bg-slate-700 text-white font-bold' : 'text-slate-400 hover:text-white'}`}
          >
            Schema-Only (16)
          </button>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search statutory categories..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#05070a] border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono-code placeholder:text-slate-600"
          />
        </div>
      </div>

      {/* Grid of Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {filteredCategories.map((cat) => (
          <div
            key={cat.code}
            className={`p-4 rounded-xl border transition-all ${
              cat.isLiveDetected
                ? 'bg-cyber-card border-blue-500/40 glow-blue'
                : 'bg-cyber-card/60 border-cyber-border opacity-85 hover:opacity-100'
            }`}
          >
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className={`text-xs font-mono-code font-bold px-2 py-0.5 rounded ${
                cat.isLiveDetected
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400'
              }`}>
                {cat.numeral}
              </span>

              {cat.isLiveDetected ? (
                <span className="flex items-center gap-1 text-[10px] font-mono-code font-bold text-emerald-400">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  LIVE DETECTOR
                </span>
              ) : (
                <span className="text-[10px] font-mono-code text-slate-500">
                  SCHEMA-REPRESENTED
                </span>
              )}
            </div>

            <h4 className="text-xs font-bold text-slate-100 mb-1 leading-snug">
              {cat.name}
            </h4>

            <p className="text-[11px] text-slate-400 leading-relaxed">
              {cat.description}
            </p>

            {cat.detectionRuleId && (
              <div className="mt-2.5 pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono-code">
                <span className="text-slate-500">Engine Rule:</span>
                <span className="text-amber-300">{cat.detectionRuleId}</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Regulatory Context Box */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
        <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold text-slate-200 block mb-0.5">
            Statutory Legal Foundation (AGENTS.md Rule 1)
          </span>
          <p className="leading-relaxed">
            Barbarika’s data models encompass all 20 incident categories identified in the CERT-In Directions 2022. For the 36-hour hackathon prototype, 3 core high-impact attack vectors are live-detected and tested via telemetry correlation, alongside the dead-man's switch for Candidate Category (ii).
          </p>
        </div>
      </div>

    </div>
  );
};
