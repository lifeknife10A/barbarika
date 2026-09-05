import React, { useState, useEffect } from 'react';
import { 
  Server, 
  ShieldCheck, 
  Lock, 
  Activity, 
  HardDrive, 
  ArrowRight, 
  Cpu, 
  Zap, 
  CheckCircle2,
  AlertOctagon,
  Radio,
  KeyRound
} from 'lucide-react';

export default function DualNodeStatus({ 
  primaryState = "HEALTHY",
  watchdogState = "WATCHING",
  heartbeatCount = 1842,
  recordsIndexed = 47,
  tamperCount = 0
}) {
  const [ticker, setTicker] = useState(5);
  const [packetActive, setPacketActive] = useState(false);

  useEffect(() => {
    if (primaryState === "KILLED") {
      setTicker(0);
      return;
    }

    const interval = setInterval(() => {
      setTicker((prev) => {
        if (prev <= 1) {
          setPacketActive(true);
          setTimeout(() => setPacketActive(false), 800);
          return 5;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [primaryState]);

  const isPrimaryKilled = primaryState === "KILLED";
  const isPrimaryCompromised = primaryState === "COMPROMISED";
  const isWatchdogTripped = watchdogState === "SUSPECTED_COMPROMISE";

  return (
    <div className="rounded-xl border border-slate-800 bg-[#080d1a]/90 p-3.5 flex flex-col justify-between shadow-lg relative overflow-hidden">
      
      {/* Background Accent Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a15_1px,transparent_1px),linear-gradient(to_bottom,#0f172a15_1px,transparent_1px)] bg-[size:16px_16px] pointer-events-none opacity-50" />

      {/* Header */}
      <div className="flex items-center justify-between pb-2.5 border-b border-slate-800/80 mb-3 relative z-10">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-100 flex items-center gap-1.5">
              Dual-Node Enclave Architecture
            </h3>
            <p className="text-[10px] text-slate-400 font-sans">
              Air-gapped telemetry via one-way mTLS 1.3 stream
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-[10px]">
          <Lock className="w-2.5 h-2.5" />
          <span>0 Inbound Ports Open</span>
        </div>
      </div>

      {/* Topology Nodes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono relative z-10">
        
        {/* Node 1: Monitored Primary Server */}
        <div className={`p-3 rounded-lg border transition-all ${
          isPrimaryKilled 
            ? 'bg-rose-950/30 border-rose-600/60 shadow-[0_0_15px_rgba(225,29,72,0.2)]' 
            : isPrimaryCompromised
            ? 'bg-amber-950/20 border-amber-500/40'
            : 'bg-[#060a14] border-slate-800/80 hover:border-slate-700'
        }`}>
          <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-slate-800/60">
            <div className="flex items-center gap-1.5">
              <Server className={`w-3.5 h-3.5 ${isPrimaryKilled ? 'text-rose-400' : 'text-slate-300'}`} />
              <span className="font-bold text-white text-[11px] truncate">primary-srv-01</span>
            </div>
            <span className={`text-[9px] px-2 py-0.5 rounded-full uppercase font-bold tracking-wide border ${
              isPrimaryKilled 
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse' 
                : isPrimaryCompromised
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
            }`}>
              {isPrimaryKilled ? 'DAEMON KILLED' : isPrimaryCompromised ? 'INTRUSION ALERT' : 'HEALTHY'}
            </span>
          </div>

          <div className="space-y-1.5 text-[10px] text-slate-400">
            <div className="flex justify-between items-center">
              <span>Go Daemon Memory:</span>
              <span className="text-slate-200 font-mono bg-slate-900 px-1.5 py-0.5 rounded">12.4 MB RAM</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Cryptographic Sign:</span>
              <span className="text-cyan-400 font-mono flex items-center gap-1">
                <KeyRound className="w-2.5 h-2.5" /> Ed25519
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span>Heartbeat Sequence:</span>
              <span className="text-amber-300 font-mono">#{heartbeatCount}</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Host Daemon Status:</span>
              <span className={isPrimaryKilled ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                {isPrimaryKilled ? 'Process Terminated (kill -9)' : 'Active Systemd Unit'}
              </span>
            </div>
          </div>
        </div>

        {/* Node 2: Isolated Black-Box Sentry Vault */}
        <div className={`p-3 rounded-lg border transition-all ${
          isWatchdogTripped
            ? 'bg-rose-950/30 border-rose-500/60 shadow-[0_0_15px_rgba(225,29,72,0.2)]'
            : 'bg-[#060a14] border-slate-800/80 hover:border-slate-700'
        }`}>
          <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-slate-800/60">
            <div className="flex items-center gap-1.5">
              <HardDrive className={`w-3.5 h-3.5 ${isWatchdogTripped ? 'text-rose-400' : 'text-cyan-400'}`} />
              <span className="font-bold text-white text-[11px] truncate">sentry-vault-01</span>
            </div>
            <span className={`text-[9px] px-2 py-0.5 rounded-full uppercase font-bold tracking-wide border ${
              isWatchdogTripped 
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse' 
                : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
            }`}>
              {isWatchdogTripped ? 'DEAD-MAN FIRED' : 'ARMED & SEALED'}
            </span>
          </div>

          <div className="space-y-1.5 text-[10px] text-slate-400">
            <div className="flex justify-between items-center">
              <span>Tamper Vault Engine:</span>
              <span className="text-slate-200 font-mono bg-slate-900 px-1.5 py-0.5 rounded">SQLite 3.45 WAL</span>
            </div>
            <div className="flex justify-between items-center">
              <span>Preserved Records:</span>
              <span className="text-emerald-400 font-mono font-bold">{recordsIndexed} Immutable Records</span>
            </div>
            <div className="flex justify-between items-center">
              <span>SHA-256 Hash Chain:</span>
              <span className="text-emerald-400 font-mono font-bold flex items-center gap-1">
                <CheckCircle2 className="w-2.5 h-2.5" /> 0 Tampering
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span>Watchdog Circuit:</span>
              <span className={isWatchdogTripped ? 'text-rose-400 font-bold' : 'text-cyan-300'}>
                {isWatchdogTripped ? 'Isolated Forensic Mode' : 'Inverted Sliding Window (5s)'}
              </span>
            </div>
          </div>
        </div>

      </div>

      {/* Watchdog Inverted Dead-Man Switch Status Bar */}
      <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono relative z-10">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Inverted Heartbeat Watchdog:</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 border border-slate-800">
            3 missed pings (15s) = Quarantine
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className={`flex h-2 w-2 relative ${isPrimaryKilled ? 'animate-none' : ''}`}>
            {packetActive && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
            )}
            <span className={`relative inline-flex rounded-full h-2 w-2 ${
              isPrimaryKilled ? 'bg-rose-500' : 'bg-cyan-400'
            }`} />
          </span>

          <span className={`font-bold ${
            isPrimaryKilled 
              ? 'text-rose-400 animate-pulse' 
              : packetActive 
              ? 'text-cyan-300' 
              : 'text-slate-400'
          }`}>
            {isPrimaryKilled 
              ? 'CRITICAL: DEAD-MAN SWITCH TRIPPED (HOST SILENCED)' 
              : `PULSE ACTIVE • T - 0${ticker}s`}
          </span>
        </div>
      </div>

    </div>
  );
}

