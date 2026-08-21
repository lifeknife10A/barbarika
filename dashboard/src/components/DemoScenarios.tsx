import React, { useState } from 'react';
import { Play, RotateCcw, Zap, Terminal, Clock, ShieldAlert, FileText, Bug } from 'lucide-react';

interface DemoScenariosProps {
  onTriggerCat3: () => void;
  onTriggerCat4: () => void;
  onTriggerCat5: () => void;
  onTriggerCat2: () => void;
  onResetClean: () => void;
  activeScenarioName: string | null;
}

export const DemoScenarios: React.FC<DemoScenariosProps> = ({
  onTriggerCat3,
  onTriggerCat4,
  onTriggerCat5,
  onTriggerCat2,
  onResetClean,
  activeScenarioName,
}) => {
  const [showPitchScript, setShowPitchScript] = useState(false);

  return (
    <div className="glass-panel rounded-xl p-4 border border-blue-500/30 bg-blue-950/10">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 mb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-blue-400" />
          <h3 className="font-bold text-white text-xs tracking-wider uppercase font-mono-code">
            STAGE DEMO ATTACK INJECTION CONTROLLER
          </h3>
          {activeScenarioName && (
            <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 text-[10px] font-mono-code font-bold">
              ACTIVE: {activeScenarioName}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowPitchScript(!showPitchScript)}
            className="text-[11px] text-blue-400 hover:text-blue-300 underline font-medium"
          >
            {showPitchScript ? 'Hide 3-Min Pitch Guide' : 'View 3-Min Pitch Guide'}
          </button>
          <button
            onClick={onResetClean}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition"
            title="Reset system to clean baseline state"
          >
            <RotateCcw className="w-3 h-3 text-slate-400" />
            <span>Reset Baseline</span>
          </button>
        </div>
      </div>

      {/* 4 Demo Scenario Trigger Buttons */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        
        {/* Cat 3 */}
        <button
          onClick={onTriggerCat3}
          className="p-2.5 rounded-lg bg-cyber-card hover:bg-slate-800/80 border border-cyber-border hover:border-blue-500/50 text-left transition group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-mono-code font-bold text-blue-400">
              PATH 1: CAT (iii)
            </span>
            <Play className="w-3 h-3 text-slate-500 group-hover:text-blue-400 transition" />
          </div>
          <p className="text-xs font-bold text-slate-100">SSH Brute-Force + Sudo</p>
          <p className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">
            14 auth failures &rarr; login &rarr; root escalation
          </p>
        </button>

        {/* Cat 4 */}
        <button
          onClick={onTriggerCat4}
          className="p-2.5 rounded-lg bg-cyber-card hover:bg-slate-800/80 border border-cyber-border hover:border-indigo-500/50 text-left transition group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-mono-code font-bold text-indigo-400">
              PATH 2: CAT (iv)
            </span>
            <Play className="w-3 h-3 text-slate-500 group-hover:text-indigo-400 transition" />
          </div>
          <p className="text-xs font-bold text-slate-100">Web-Root Defacement</p>
          <p className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">
            Nginx upload exploit &rarr; fsnotify /var/www
          </p>
        </button>

        {/* Cat 5 */}
        <button
          onClick={onTriggerCat5}
          className="p-2.5 rounded-lg bg-cyber-card hover:bg-slate-800/80 border border-cyber-border hover:border-rose-500/50 text-left transition group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-mono-code font-bold text-rose-400">
              PATH 3: CAT (v)
            </span>
            <Play className="w-3 h-3 text-slate-500 group-hover:text-rose-400 transition" />
          </div>
          <p className="text-xs font-bold text-slate-100">Ransomware & Canary</p>
          <p className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">
            58 rapid encryptions &rarr; tripwire canary
          </p>
        </button>

        {/* Candidate Cat 2 */}
        <button
          onClick={onTriggerCat2}
          className="p-2.5 rounded-lg bg-cyber-card hover:bg-slate-800/80 border border-cyber-border hover:border-purple-500/50 text-left transition group"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-mono-code font-bold text-purple-400">
              PATH 4: CANDIDATE (ii)
            </span>
            <Play className="w-3 h-3 text-slate-500 group-hover:text-purple-400 transition" />
          </div>
          <p className="text-xs font-bold text-slate-100">Dead Man Switch (Disruption)</p>
          <p className="text-[10px] text-slate-400 mt-0.5 line-clamp-1">
            Intrusion &rarr; 15s flatline &rarr; Human Review
          </p>
        </button>

      </div>

      {/* 3-Minute Grand Finale Stage Choreography Guide */}
      {showPitchScript && (
        <div className="mt-3 p-3.5 rounded-lg bg-[#05070a] border border-slate-800 text-xs space-y-2">
          <div className="flex items-center gap-1.5 text-blue-400 font-bold font-mono-code text-[11px]">
            <Clock className="w-3.5 h-3.5" />
            <span>3-MINUTE GRAND FINALE STAGE CHOREOGRAPHY (Blueprint Sec 5)</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] text-slate-300 font-mono-code">
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <strong className="text-white block">0:00 - 0:35 Hook & Nodes</strong>
              <span>Clean dark UI, 0 listeners on primary host, 6h clock standby.</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <strong className="text-white block">0:35 - 1:35 Attack & Flatline</strong>
              <span>Trigger Cat 3 &rarr; Clock starts from noticed_at &rarr; Disruption flags Candidate Cat (ii).</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <strong className="text-white block">1:35 - 3:00 Verify & Export</strong>
              <span>1-click hash chain pass &rarr; Unmask IP &rarr; Auto-draft Annexure I PDF in &lt; 3 mins.</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
