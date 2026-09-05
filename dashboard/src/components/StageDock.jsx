import React, { useState } from 'react';
import { 
  Play, 
  RotateCcw, 
  ChevronUp, 
  ChevronDown, 
  Flame, 
  Skull, 
  ShieldCheck, 
  FileCheck, 
  Radio,
  Sliders,
  Sparkles
} from 'lucide-react';

export default function StageDock({ currentStep = 1, onSelectStep, onReset }) {
  const [isExpanded, setIsExpanded] = useState(false);

  const steps = [
    { id: 1, label: '1. Baseline mTLS Ingestion', icon: Radio },
    { id: 2, label: '2. Intrusion & 6H SLA', icon: Flame },
    { id: 3, label: '3. Host Kill (kill -9)', icon: Skull },
    { id: 4, label: '4. Cryptographic Vault Audit', icon: ShieldCheck },
    { id: 5, label: '5. Pre-Filled Annexure I', icon: FileCheck }
  ];

  return (
    <div className="fixed bottom-4 right-4 z-40">
      <div className="rounded-xl bg-[#080d1a]/95 backdrop-blur-xl border border-slate-800 shadow-2xl p-2 font-mono text-xs text-slate-200">
        <div className="flex items-center gap-2">
          
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-700 transition-colors cursor-pointer"
          >
            <Sliders className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-[11px] font-bold">Pitch Mode: Step {currentStep}/5</span>
            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />}
          </button>

          {/* Direct Quick Next Button */}
          {currentStep < 5 && (
            <button
              onClick={() => onSelectStep(currentStep + 1)}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-bold text-[11px] transition-all cursor-pointer shadow-md border border-rose-500/40"
            >
              Next Step →
            </button>
          )}

          <button
            onClick={onReset}
            className="p-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-white border border-slate-700 transition-colors cursor-pointer"
            title="Reset Demo to Step 1"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Expanded Drawer for All 5 Steps */}
        {isExpanded && (
          <div className="mt-2 pt-2 border-t border-slate-800 grid grid-cols-1 gap-1">
            {steps.map((step) => {
              const Icon = step.icon;
              const isActive = currentStep === step.id;
              return (
                <button
                  key={step.id}
                  onClick={() => onSelectStep(step.id)}
                  className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-left text-xs transition-colors cursor-pointer ${
                    isActive 
                      ? 'bg-rose-950/50 text-rose-300 font-bold border border-rose-600/50 shadow-inner' 
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-rose-400' : 'text-slate-500'}`} />
                  <span>{step.label}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

