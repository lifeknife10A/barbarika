import React from 'react';
import { Shield, Server, Lock, Activity, Eye, FileText, CheckCircle2, AlertTriangle } from 'lucide-react';
import { NodeHealth, WatchdogState } from '../types';

interface HeaderProps {
  health: NodeHealth;
  activeTab: 'overview' | 'events' | 'provenance' | 'vault' | 'audit' | 'categories';
  setActiveTab: (tab: 'overview' | 'events' | 'provenance' | 'vault' | 'audit' | 'categories') => void;
  onOpenAudit: () => void;
  unmaskAuditCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  activeTab,
  setActiveTab,
  onOpenAudit,
  unmaskAuditCount,
}) => {
  const getWatchdogBadge = (state: WatchdogState) => {
    switch (state) {
      case 'HEALTHY':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            WATCHDOG: HEALTHY
          </span>
        );
      case 'TELEMETRY_LOSS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            TELEMETRY LOSS (15s)
          </span>
        );
      case 'SUSPECTED_HOST_COMPROMISE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/50 animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            SUSPECTED HOST COMPROMISE
          </span>
        );
    }
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyber-border bg-[#0a0d14]/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-400 shadow-lg shadow-blue-500/10">
              <Shield className="w-6 h-6" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2 font-mono-code">
                  BARBARIKA <span className="text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-sans font-medium border border-blue-500/30">SIH 2026</span>
                </h1>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Evidence-Preserving CERT-In Incident Readiness & Reporting Platform
              </p>
            </div>
          </div>

          {/* Node Health Pills */}
          <div className="hidden lg:flex items-center gap-3 text-xs">
            {/* Primary Agent */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border">
              <div className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-slate-300 font-medium">Primary:</span>
                <span className={`font-mono-code ${health.primary_agent.status === 'ONLINE' ? 'text-emerald-400' : 'text-rose-400 font-bold'}`}>
                  {health.primary_agent.status}
                </span>
              </div>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400 font-mono-code text-[11px]">0 Listeners (Egress mTLS)</span>
            </div>

            {/* Sentry Vault */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-card border border-cyber-border">
              <div className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-indigo-400" />
                <span className="text-slate-300 font-medium">Sentry Vault:</span>
                <span className="text-indigo-400 font-mono-code">SQLite WAL</span>
              </div>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400 font-mono-code text-[11px]">{health.sentry_host.chain_length} Blocks</span>
            </div>

            {/* Watchdog Status */}
            <div>
              {getWatchdogBadge(health.sentry_host.watchdog_state)}
            </div>
          </div>

          {/* Nav & Audit Access */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => onOpenAudit()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Audit trail for role-gated identifier unmasking"
            >
              <Eye className="w-3.5 h-3.5 text-amber-400" />
              <span>Audit Log</span>
              {unmaskAuditCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full bg-amber-500/20 text-amber-400 text-[10px] font-mono-code font-bold">
                  {unmaskAuditCount}
                </span>
              )}
            </button>

            <div className="h-6 w-px bg-cyber-border mx-1"></div>

            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-7 h-7 rounded-full bg-blue-600/30 border border-blue-500/40 flex items-center justify-center font-bold text-blue-300 text-[11px]">
                NC
              </div>
              <div className="hidden md:block text-left">
                <p className="font-semibold text-slate-200 leading-tight text-[11px]">Nandini C.</p>
                <p className="text-[10px] text-slate-400 leading-tight">CISO Reviewer</p>
              </div>
            </div>
          </div>

        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 -mb-px overflow-x-auto text-xs font-medium border-t border-cyber-border/60 pt-2 pb-2">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition ${
              activeTab === 'overview'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-card'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            CISO Overview
          </button>
          
          <button
            onClick={() => setActiveTab('provenance')}
            className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition ${
              activeTab === 'provenance'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-card'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Provenance Graph (DAG)
          </button>

          <button
            onClick={() => setActiveTab('vault')}
            className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition ${
              activeTab === 'vault'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-card'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            Tamper-Evident Vault
          </button>

          <button
            onClick={() => setActiveTab('events')}
            className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition ${
              activeTab === 'events'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-card'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Live Telemetry Feed
          </button>

          <button
            onClick={() => setActiveTab('categories')}
            className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition ${
              activeTab === 'categories'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-card'
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            Taxonomy (20/20 Schema, 3 Live)
          </button>
        </div>

      </div>
    </header>
  );
};
