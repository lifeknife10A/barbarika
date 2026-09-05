import React from 'react';
import { 
  Flame, 
  Skull, 
  ShieldCheck, 
  FileCheck, 
  Radio, 
  ChevronRight, 
  RotateCcw, 
  Play 
} from 'lucide-react';

export default function StageChoreographer({ 
  currentStep = 1, 
  onSelectStep, 
  onReset 
}) {
  const steps = [
    {
      id: 1,
      time: "0:00 – 0:15",
      title: "1. The Hook",
      desc: "Baseline Nominal",
      icon: Radio
    },
    {
      id: 2,
      time: "0:35 – 1:05",
      title: "2. Attack Injection",
      desc: "Brute Force Tripped",
      icon: Flame
    },
    {
      id: 3,
      time: "1:05 – 1:35",
      title: "3. Host Destruction",
      desc: "kill -9 Flatline",
      icon: Skull
    },
    {
      id: 4,
      time: "1:35 – 2:05",
      title: "4. Verify Vault",
      desc: "SHA-256 Audit",
      icon: ShieldCheck
    },
    {
      id: 5,
      time: "2:05 – 3:00",
      title: "5. Review & Export",
      desc: "Annexure I Filing",
      icon: FileCheck
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6">
      <div className="p-1 rounded-full bg-white/[0.03] ring-1 ring-white/10 shadow-lg flex flex-wrap items-center justify-between gap-2">
        
        {/* Step Trigger Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto py-0.5 px-1">
          {steps.map((step) => {
            const Icon = step.icon;
            const isActive = currentStep === step.id;
            const isCompleted = currentStep > step.id;

            return (
              <button
                key={step.id}
                onClick={() => onSelectStep(step.id)}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-sans transition-all duration-300 cursor-pointer ${
                  isActive
                    ? 'bg-gradient-to-r from-sky-500 to-sky-600 text-white font-semibold shadow-md shadow-sky-500/30 scale-105'
                    : isCompleted
                    ? 'bg-white/[0.04] text-emerald-300 border border-emerald-500/30 hover:bg-white/[0.08]'
                    : 'bg-white/[0.02] text-slate-400 border border-transparent hover:text-white hover:bg-white/[0.06]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : isCompleted ? 'text-emerald-400' : 'text-slate-400'}`} />
                <span>{step.title}</span>
                <span className="text-[10px] opacity-70 font-mono hidden md:inline">({step.time})</span>
              </button>
            );
          })}
        </div>

        {/* Step Controls */}
        <div className="flex items-center gap-2 pr-2">
          {currentStep < 5 && (
            <button
              onClick={() => onSelectStep(currentStep + 1)}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-semibold font-sans bg-sky-500 hover:bg-sky-400 text-slate-950 transition-all shadow-md shadow-sky-500/20 active:scale-[0.98] cursor-pointer"
            >
              <span>Next Stage</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}

          <button
            onClick={onReset}
            className="w-7 h-7 rounded-full bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 hover:text-white flex items-center justify-center transition-colors cursor-pointer border border-white/5"
            title="Reset to Step 1"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>
    </div>
  );
}
