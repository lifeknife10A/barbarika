import React from 'react';
import { Terminal, GitBranch, ShieldCheck, Server } from 'lucide-react';

export default function TabsNavigation({ activeTab, onSelectTab, eventCount = 13, vaultRecords = 47 }) {
  const tabs = [
    { id: 'FEED', label: 'Live Ingest & Triage', icon: Terminal, badge: `${eventCount} Events` },
    { id: 'PROVENANCE', label: 'Evidence Lineage (DAG)', icon: GitBranch, badge: 'Deterministic' },
    { id: 'VAULT', label: 'Cryptographic Vault', icon: ShieldCheck, badge: `${vaultRecords} Records` },
    { id: 'INFRA', label: 'Node Infrastructure', icon: Server, badge: 'mTLS 1.3' },
  ];

  return (
    <div className="border-b border-white/[0.08] bg-[#060a12]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center gap-6 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`flex items-center gap-2 py-3 text-xs font-sans font-medium transition-colors cursor-pointer border-b-2 whitespace-nowrap ${
                isActive
                  ? 'text-white border-sky-400 font-semibold'
                  : 'text-slate-400 border-transparent hover:text-slate-200'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
              <span>{tab.label}</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                isActive 
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20' 
                  : 'bg-white/[0.04] text-slate-500'
              }`}>
                {tab.badge}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
