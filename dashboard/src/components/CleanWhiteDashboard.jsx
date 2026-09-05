import React, { useState, useEffect, useRef } from 'react';
import { 
  Cpu, 
  Activity, 
  HardDrive, 
  Server, 
  Radio, 
  Flame, 
  AlertTriangle, 
  ShieldCheck, 
  Search, 
  FileText, 
  CheckCircle2, 
  Clock, 
  Zap, 
  Globe,
  Layers, 
  ArrowUpRight, 
  Sliders, 
  Lock, 
  RefreshCw,
  Terminal,
  ChevronRight,
  TrendingUp,
  AlertCircle,
  X
} from 'lucide-react';

export default function CleanWhiteDashboard({ onOpenReport }) {
  // 1. Sudden Log Spike state ("If the logs increase suddenly then make the colour red")
  const [isSpikeActive, setIsSpikeActive] = useState(false);
  
  // 2. Events Per Minute (EPM) historical data stream
  const [epmHistory, setEpmHistory] = useState([
    160, 182, 175, 194, 188, 205, 190, 184, 210, 195, 188, 202, 196, 215, 208
  ]);
  const [currentEpm, setCurrentEpm] = useState(208);

  // 3. System Health live states
  const [cpuLoad, setCpuLoad] = useState(24);
  const [gpuLoad, setGpuLoad] = useState(18);
  const [ramUsedGb, setRamUsedGb] = useState(4.2);
  const [diskWriteMb, setDiskWriteMb] = useState(16.4);
  const [networkMbps, setNetworkMbps] = useState(1.8);

  // 3b. Sentry Health & Enclave Watchdog live states
  const [sentryTicker, setSentryTicker] = useState(5);
  const [sentryPulse, setSentryPulse] = useState(false);
  const [sentryRecords, setSentryRecords] = useState(47);

  // 4. Incoming live logs state
  const [logFilter, setLogFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);

  const initialLogs = [
    {
      id: 1042,
      time: "18:14:02",
      facility: "auth.log",
      service: "sshd",
      severity: "INFO",
      ip: "192.168.10.45",
      raw: "sshd[19284]: Connection established from 192.168.10.45 port 54822 [user=deploy-svc]",
      hash: "7a52e6ff74e2d3b4f621a364be16a5ef"
    },
    {
      id: 1043,
      time: "18:14:08",
      facility: "nginx/access.log",
      service: "nginx",
      severity: "INFO",
      ip: "10.0.4.18",
      raw: "GET /api/v1/health HTTP/1.1 200 OK 0.002s client=10.0.4.18 user_agent='Barbarika-Probe/1.4'",
      hash: "b8971fa8d39c018274d817f09c840c03"
    },
    {
      id: 1044,
      time: "18:14:15",
      facility: "kernel",
      service: "systemd",
      severity: "NOTICE",
      ip: "127.0.0.1",
      raw: "systemd[1]: barbarika-sentry.service: Sent 5s sliding heartbeat seq #1842 host=127.0.0.1",
      hash: "c20491b920194817a02b4891823a1105"
    },
    {
      id: 1045,
      time: "18:14:22",
      facility: "auth.log",
      service: "sshd",
      severity: "WARN",
      ip: "198.51.100.74",
      raw: "sshd[19290]: Failed password for invalid user admin from 198.51.100.74 port 43210",
      hash: "d94103c819273948b8192837492fe229"
    },
    {
      id: 1046,
      time: "18:14:31",
      facility: "nginx/access.log",
      service: "nginx",
      severity: "INFO",
      ip: "203.0.113.19",
      raw: "POST /api/v1/telemetry HTTP/1.1 200 OK client=203.0.113.19 bytes_sent=1420",
      hash: "e48109bf84172a5b6c9381014ab4219d"
    }
  ];

  const [logs, setLogs] = useState(initialLogs);
  const logsContainerRef = useRef(null);

  // EPM Ticker & Health Fluctuation
  useEffect(() => {
    const interval = setInterval(() => {
      if (isSpikeActive) {
        // Sudden spike values (>2,400 EPM, red zone)
        const spikeVal = Math.floor(2400 + Math.random() * 600);
        setCurrentEpm(spikeVal);
        setEpmHistory(prev => [...prev.slice(1), spikeVal]);
        setCpuLoad(Math.floor(78 + Math.random() * 14));
        setGpuLoad(Math.floor(45 + Math.random() * 20));
        setRamUsedGb(Number((6.8 + Math.random() * 0.8).toFixed(1)));
        setDiskWriteMb(Number((84.5 + Math.random() * 25).toFixed(1)));
        setNetworkMbps(Number((42.1 + Math.random() * 15).toFixed(1)));

        // Inject burst attack logs with visible IP addresses
        const attackerIps = ["198.51.100.74", "203.0.113.19", "185.220.101.5", "194.26.29.112", "45.142.214.7"];
        const selectedIp = attackerIps[Math.floor(Math.random() * attackerIps.length)];
        const newAttackLog = {
          id: Date.now() % 100000,
          time: new Date().toLocaleTimeString(),
          facility: "auth.log",
          service: "sshd",
          severity: "CRITICAL",
          ip: selectedIp,
          raw: `sshd[${Math.floor(20000 + Math.random() * 5000)}]: High-frequency password spray attempt detected from ${selectedIp} (root privilege targeting)`,
          hash: Math.random().toString(16).substring(2, 34)
        };
        setLogs(prev => [newAttackLog, ...prev.slice(0, 35)]);
        setSentryRecords(prev => prev + 1);
      } else {
        // Normal baseline values (~170-220 EPM, calm blue zone)
        const normalVal = Math.floor(175 + Math.random() * 45);
        setCurrentEpm(normalVal);
        setEpmHistory(prev => [...prev.slice(1), normalVal]);
        setCpuLoad(Math.floor(21 + Math.random() * 7));
        setGpuLoad(Math.floor(16 + Math.random() * 5));
        setRamUsedGb(Number((4.1 + Math.random() * 0.3).toFixed(1)));
        setDiskWriteMb(Number((15.2 + Math.random() * 4).toFixed(1)));
        setNetworkMbps(Number((1.6 + Math.random() * 0.6).toFixed(1)));

        // Occasionally inject normal operational logs
        if (Math.random() > 0.6) {
          const internalIps = ["192.168.1.104", "10.0.4.18", "172.16.0.42", "192.168.10.45", "10.240.0.12"];
          const normalIp = internalIps[Math.floor(Math.random() * internalIps.length)];
          const sampleLog = {
            id: Date.now() % 100000,
            time: new Date().toLocaleTimeString(),
            facility: Math.random() > 0.5 ? "nginx/access.log" : "journald",
            service: Math.random() > 0.5 ? "nginx" : "barbarika-daemon",
            severity: "INFO",
            ip: normalIp,
            raw: `GET /api/v1/telemetry/heartbeat 200 OK from ${normalIp} - mTLS verified - 0 byte loss`,
            hash: Math.random().toString(16).substring(2, 34)
          };
          setLogs(prev => [sampleLog, ...prev.slice(0, 35)]);
        }
      }
    }, 1800);

    return () => clearInterval(interval);
  }, [isSpikeActive]);

  // Sentry Watchdog 5-second inverted heartbeat ticker & pulse
  useEffect(() => {
    const timer = setInterval(() => {
      setSentryTicker(prev => {
        if (prev <= 1) {
          setSentryPulse(true);
          setTimeout(() => setSentryPulse(false), 750);
          return 5;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // SVG Chart path calculation
  const maxChartVal = 3200;
  const chartHeight = 140;
  const chartWidth = 500;
  const points = epmHistory.map((val, idx) => {
    const x = (idx / (epmHistory.length - 1)) * chartWidth;
    const y = chartHeight - (val / maxChartVal) * chartHeight;
    return `${x},${y}`;
  });
  const linePath = `M ${points.join(' L ')}`;
  const areaPath = `M 0,${chartHeight} L ${points.join(' L ')} L ${chartWidth},${chartHeight} Z`;

  // Filter logs by tab and search query (matches IP, message, service, ID)
  const filteredLogs = logs.filter(log => {
    if (logFilter === 'CRITICAL' && log.severity !== 'CRITICAL') return false;
    if (logFilter === 'WARN' && log.severity !== 'WARN' && log.severity !== 'CRITICAL') return false;
    if (logFilter === 'AUTH' && !log.facility.includes('auth')) return false;
    if (logFilter === 'NGINX' && !log.facility.includes('nginx')) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const content = (log.raw || '').toLowerCase();
      const ip = (log.ip || '').toLowerCase();
      const service = (log.service || '').toLowerCase();
      return content.includes(q) || ip.includes(q) || service.includes(q) || String(log.id).includes(q);
    }
    return true;
  });

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0 overflow-y-auto pr-1">
      


      {/* ========================================================================= */}
      {/* 2. DUAL ENCLAVE HEALTH: SYSTEM HEALTH (LEFT) & SENTRY HEALTH (RIGHT)       */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 shrink-0">
        
        {/* PANEL 1: SYSTEM HEALTH (PRIMARY MONITORED SERVER) */}
        <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 shadow-xs hover:border-slate-300 transition-all flex flex-col justify-between">
          {/* Header */}
          <div className="flex items-center justify-between pb-2.5 border-b border-slate-100 mb-2.5">
            <div className="flex items-center gap-2.5">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center border transition-all ${
                isSpikeActive ? 'bg-rose-50 text-rose-600 border-rose-200' : 'bg-indigo-50 text-indigo-600 border-indigo-200'
              }`}>
                <Server className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-sans">
                    System Health
                  </h2>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 font-semibold">
                    primary-srv-01
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  Monitored Production Host • Linux 6.8 LTS
                </p>
              </div>
            </div>

            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10.5px] font-mono font-bold uppercase border ${
              isSpikeActive 
                ? 'bg-rose-50 text-rose-700 border-rose-200 animate-pulse' 
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${isSpikeActive ? 'bg-rose-500' : 'bg-emerald-500'}`} />
              {isSpikeActive ? 'SURGE LOAD' : 'NOMINAL'}
            </span>
          </div>

          {/* Sub-grid of System Metrics */}
          <div className="grid grid-cols-3 gap-2 text-xs">
            {/* CPU */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <Cpu className="w-3 h-3 text-indigo-500" /> CPU Load
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-white text-slate-700 border border-slate-200">
                  12 Cores
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-900">{cpuLoad}%</span>
                <span className="text-[10px] font-mono text-slate-400">3.8 GHz</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div 
                  style={{ width: `${cpuLoad}%` }} 
                  className={`h-full rounded-full transition-all duration-500 ${cpuLoad > 60 ? 'bg-rose-500' : 'bg-indigo-600'}`}
                />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block">
                Temp: {isSpikeActive ? '68°C' : '44°C'}
              </span>
            </div>

            {/* RAM & GPU */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <Radio className="w-3 h-3 text-sky-500" /> Memory
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-white text-slate-700 border border-slate-200">
                  DDR5
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-900">{ramUsedGb} GB</span>
                <span className="text-[10px] font-mono text-slate-400">/ 16 GB</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div 
                  style={{ width: `${(ramUsedGb / 16) * 100}%` }} 
                  className="h-full bg-sky-500 rounded-full transition-all duration-500"
                />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block">
                GPU: {gpuLoad}% (RTX 4070)
              </span>
            </div>

            {/* Go Telemetry Daemon */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <Activity className="w-3 h-3 text-emerald-500" /> Go Daemon
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                  Ed25519
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-900">&lt;15 MB</span>
                <span className="text-[10px] font-mono text-emerald-600 font-semibold">Active Unit</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div style={{ width: '22%' }} className="h-full bg-emerald-500 rounded-full" />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block">
                Egress Only • Outbound mTLS
              </span>
            </div>
          </div>
        </div>

        {/* PANEL 2: SENTRY HEALTH (ISOLATED ENCLAVE & WATCHDOG) */}
        <div className="bg-white rounded-xl border border-slate-200/90 p-3.5 shadow-xs hover:border-slate-300 transition-all flex flex-col justify-between">
          {/* Header */}
          <div className="flex items-center justify-between pb-2.5 border-b border-slate-100 mb-2.5">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-sans">
                    Sentry Health
                  </h2>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 font-semibold">
                    sentry-vault-01
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 font-sans">
                  Isolated Black-Box Enclave • Hardened Micro-VM
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-600 font-mono text-[10px] font-bold">
                <Lock className="w-3 h-3 text-emerald-600" />
                <span>0 Inbound Open</span>
              </span>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10.5px] font-mono font-bold uppercase border ${
                isSpikeActive 
                  ? 'bg-rose-50 text-rose-700 border-rose-200' 
                  : 'bg-cyan-50 text-cyan-800 border-cyan-200'
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${isSpikeActive ? 'bg-rose-500' : 'bg-cyan-500'}`} />
                {isSpikeActive ? 'SURGE CAPTURE' : 'ARMED & SEALED'}
              </span>
            </div>
          </div>

          {/* Sub-grid of Sentry Metrics */}
          <div className="grid grid-cols-3 gap-2 text-xs">
            {/* Inverted Watchdog with live pulse ticker */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <Clock className="w-3 h-3 text-amber-500" /> Watchdog
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-amber-50 text-amber-800 border border-amber-200">
                  5s Window
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <div className="flex items-center gap-1.5">
                  <span className={`relative flex h-2 w-2`}>
                    {sentryPulse && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    )}
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                  </span>
                  <span className="text-lg font-bold font-mono text-slate-900">
                    T - 0{sentryTicker}s
                  </span>
                </div>
                <span className="text-[10px] font-mono text-emerald-600 font-bold">Pulse OK</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div 
                  style={{ width: `${(sentryTicker / 5) * 100}%` }} 
                  className="h-full bg-amber-500 rounded-full transition-all duration-300"
                />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block truncate">
                Dead-Man Switch • 3 Missed = Trip
              </span>
            </div>

            {/* SQLite WAL Storage */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <HardDrive className="w-3 h-3 text-sky-500" /> Vault Storage
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-sky-50 text-sky-700 border border-sky-200">
                  WAL Mode
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-900">{diskWriteMb} MB/s</span>
                <span className="text-[10px] font-mono text-slate-400">SQLite 3.45</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div 
                  style={{ width: `${Math.min(100, diskWriteMb)}%` }} 
                  className={`h-full rounded-full transition-all duration-500 ${diskWriteMb > 50 ? 'bg-amber-500' : 'bg-sky-500'}`}
                />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block truncate">
                Append-Only Write-Ahead Log
              </span>
            </div>

            {/* Cryptographic Hash Chain & Tamper Integrity */}
            <div className="p-2.5 rounded-lg bg-slate-50/80 border border-slate-100 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-500 font-sans font-semibold uppercase tracking-wider flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600" /> Hash Chain
                </span>
                <span className="text-[10px] font-mono font-bold px-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                  0 Tamper
                </span>
              </div>
              <div className="flex items-baseline justify-between mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-900">{sentryRecords} Blocks</span>
                <span className="text-[10px] font-mono text-emerald-600 font-bold">100% Intact</span>
              </div>
              <div className="w-full bg-slate-200/70 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div style={{ width: '100%' }} className="h-full bg-emerald-500 rounded-full" />
              </div>
              <span className="text-[9.5px] font-sans text-slate-400 mt-1 block truncate">
                SHA-256 Recursive Chain Anchor
              </span>
            </div>
          </div>
        </div>

      </div>

      {/* ========================================================================= */}
      {/* 3. DUAL-COLUMN WORKSPACE: EPM GRAPH (LEFT) & INCOMING LOGS (RIGHT)        */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 min-h-0 flex-1">
        
        {/* ----------------------------------------------------------------------- */}
        {/* LEFT PANE (4 COLS): EVENTS PER MINUTE GRAPH (DYNAMIC RED ON SPIKE)      */}
        {/* ----------------------------------------------------------------------- */}
        <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200/90 p-4 shadow-xs flex flex-col justify-between">
          <div className="flex flex-col gap-3">
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <TrendingUp className={`w-4 h-4 ${isSpikeActive ? 'text-rose-500' : 'text-blue-600'}`} />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-sans">
                  Events Per Minute
                </h3>
              </div>

              {/* Clickable EPM Badge */}
              <button
                onClick={() => setIsSpikeActive(!isSpikeActive)}
                className={`px-2.5 py-1 rounded-lg font-mono text-xs font-bold border transition-all cursor-pointer flex items-center gap-1.5 ${
                  isSpikeActive 
                    ? 'bg-rose-50 border-rose-300 text-rose-700 animate-pulse' 
                    : 'bg-blue-50 border-blue-200 text-blue-700 hover:bg-blue-100'
                }`}
                title="Click to toggle spike mode"
              >
                <Zap className={`w-3.5 h-3.5 ${isSpikeActive ? 'text-rose-600 fill-rose-600' : 'text-blue-600'}`} />
                <span>{currentEpm} EPM</span>
              </button>
            </div>

            {/* Spike Alert Banner if logs increased suddenly */}
            {isSpikeActive && (
              <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center gap-2 font-sans animate-pulse">
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                <div className="truncate text-[11px]">
                  <span className="font-bold">CRITICAL SPIKE:</span> Volume surged +940%!
                </div>
              </div>
            )}

            {/* SVG Interactive Velocity Graph */}
            <div className={`relative rounded-xl p-3 border transition-all ${
              isSpikeActive 
                ? 'bg-rose-50/40 border-rose-200' 
                : 'bg-slate-50/60 border-slate-100'
            }`}>
              <div className="flex justify-between items-center text-[10px] font-sans text-slate-400 mb-1">
                <span>3,200 EPM (Spike Threshold)</span>
                <span className={isSpikeActive ? 'text-rose-600 font-bold' : 'text-blue-600 font-bold'}>
                  {isSpikeActive ? '● CRITICAL SPIKE' : '● NOMINAL INGESTION'}
                </span>
              </div>

              {/* SVG Canvas Area Chart */}
              <svg 
                viewBox={`0 0 ${chartWidth} ${chartHeight}`} 
                className="w-full h-36 overflow-visible"
              >
                <defs>
                  {/* Normal Blue Gradient */}
                  <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
                  </linearGradient>

                  {/* Spike Red Gradient */}
                  <linearGradient id="redGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity="0.35" />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Grid guidelines */}
                <line x1="0" y1="35" x2={chartWidth} y2="35" stroke="#e2e8f0" strokeDasharray="3,3" />
                <line x1="0" y1="70" x2={chartWidth} y2="70" stroke="#e2e8f0" strokeDasharray="3,3" />
                <line x1="0" y1="105" x2={chartWidth} y2="105" stroke="#e2e8f0" strokeDasharray="3,3" />

                {/* Shaded Area */}
                <path 
                  d={areaPath} 
                  fill={isSpikeActive ? "url(#redGradient)" : "url(#blueGradient)"} 
                  className="transition-all duration-700"
                />

                {/* Stroke Line (Red on Spike, Blue on Normal) */}
                <path 
                  d={linePath} 
                  fill="none" 
                  stroke={isSpikeActive ? "#ef4444" : "#2563eb"} 
                  strokeWidth="2.5" 
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="transition-all duration-700"
                />

                {/* Data Points */}
                {epmHistory.map((val, idx) => {
                  const x = (idx / (epmHistory.length - 1)) * chartWidth;
                  const y = chartHeight - (val / maxChartVal) * chartHeight;
                  const isLatest = idx === epmHistory.length - 1;
                  return (
                    <circle 
                      key={idx}
                      cx={x}
                      cy={y}
                      r={isLatest ? 4.5 : 2}
                      fill={isSpikeActive ? "#ef4444" : "#2563eb"}
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      className={isLatest ? "animate-ping" : ""}
                    />
                  );
                })}
              </svg>

              <div className="flex justify-between items-center text-[10px] font-sans text-slate-400 mt-2">
                <span>T - 30m</span>
                <span>T - 15m</span>
                <span>Live Now</span>
              </div>
            </div>

            {/* Ingestion Velocity Details */}
            <div className="grid grid-cols-3 gap-2 mt-2 text-xs">
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold tracking-wider">AVG VELOCITY</span>
                <span className="text-slate-800 font-bold font-mono">{isSpikeActive ? '2,640 EPM' : '192 EPM'}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold tracking-wider">PEAK INGEST</span>
                <span className={`font-bold font-mono ${isSpikeActive ? 'text-rose-600' : 'text-blue-600'}`}>
                  {isSpikeActive ? '3,012 EPM' : '234 EPM'}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-100">
                <span className="text-slate-400 block text-[10px] font-sans font-semibold tracking-wider">STATUS</span>
                <span className={`font-bold font-mono ${isSpikeActive ? 'text-rose-600' : 'text-emerald-600'}`}>
                  {isSpikeActive ? 'SURGE' : 'STEADY'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ----------------------------------------------------------------------- */}
        {/* RIGHT PANE (8 COLS): INCOMING LOGS STREAM AS HIGH-END LOG TABLE          */}
        {/* ----------------------------------------------------------------------- */}
        <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200/90 shadow-xs flex flex-col min-h-0 overflow-hidden">
          
          {/* Header & Controls Toolbar */}
          <div className="p-3.5 border-b border-slate-200/80 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 shrink-0 bg-white">
            
            {/* Title & Live Badge */}
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-slate-900 text-white flex items-center justify-center shadow-xs">
                <Terminal className="w-3.5 h-3.5 text-slate-100" />
              </div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
                  Incoming Logs Feed
                </h3>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-sans font-semibold">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  {filteredLogs.length} Events
                </span>
              </div>
            </div>

            {/* Filter Tabs & Search Controls */}
            <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
              {/* Filter Pills */}
              <div className="flex items-center gap-0.5 bg-slate-100 p-0.5 rounded-lg border border-slate-200/80 font-sans text-xs">
                {['ALL', 'CRITICAL', 'WARN', 'AUTH', 'NGINX'].map(f => (
                  <button
                    key={f}
                    onClick={() => setLogFilter(f)}
                    className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                      logFilter === f
                        ? 'bg-white text-slate-900 shadow-xs font-semibold'
                        : 'text-slate-500 hover:text-slate-900 font-medium'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>

              {/* Search Box */}
              <div className="relative w-44 sm:w-56">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter logs or IP..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-8 pr-2.5 py-1 text-xs font-sans bg-slate-50 border border-slate-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-all"
                />
              </div>

              {/* Reset button */}
              <button
                onClick={() => { setLogs(initialLogs); setSearchQuery(''); setLogFilter('ALL'); }}
                className="p-1.5 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 border border-slate-200 transition-all cursor-pointer"
                title="Reset log feed"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Structured Column Headers Bar */}
          <div className="bg-slate-50/90 border-b border-slate-200/80 px-4 py-2 font-sans text-[10.5px] font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-4 shrink-0 select-none">
            <span className="w-20 shrink-0">Time</span>
            <span className="w-20 shrink-0">Level</span>
            <span className="w-32 shrink-0">Source IP</span>
            <span className="w-24 shrink-0">Service</span>
            <span className="flex-1">Event Message</span>
            <span className="w-16 text-right shrink-0 hidden xl:block">Digest</span>
          </div>

          {/* Scrollable Live Log Stream */}
          <div 
            ref={logsContainerRef}
            className="flex-1 min-h-[280px] max-h-[420px] overflow-y-auto divide-y divide-slate-100 font-mono text-xs"
          >
            {filteredLogs.map(log => {
              const isSelected = selectedLog?.id === log.id;
              return (
                <div
                  key={log.id}
                  onClick={() => setSelectedLog(isSelected ? null : log)}
                  className={`px-4 py-2.5 flex items-center gap-4 transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-indigo-50/80 border-l-3 border-l-indigo-600' 
                      : 'hover:bg-slate-50/90 even:bg-slate-50/25'
                  } ${log.severity === 'CRITICAL' ? 'bg-rose-50/35 hover:bg-rose-50/50' : ''}`}
                >
                  {/* 1. Time & ID */}
                  <div className="w-20 shrink-0 font-mono">
                    <span className="text-xs font-bold text-slate-800 block">{log.time}</span>
                    <span className="text-[10px] text-slate-400 block">#{log.id}</span>
                  </div>

                  {/* 2. Level / Severity Badge */}
                  <div className="w-20 shrink-0">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                      log.severity === 'CRITICAL'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : log.severity === 'ALERT' || log.severity === 'WARN'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        log.severity === 'CRITICAL' ? 'bg-rose-500' :
                        log.severity === 'ALERT' || log.severity === 'WARN' ? 'bg-amber-500' : 'bg-slate-400'
                      }`} />
                      {log.severity}
                    </span>
                  </div>

                  {/* 3. Source IP (Fixed width, vertically aligned across all rows!) */}
                  <div className="w-32 shrink-0">
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-blue-50/80 text-blue-700 border border-blue-200/70 text-xs font-mono font-semibold">
                      <Globe className="w-3 h-3 text-blue-500 shrink-0" />
                      <span>{log.ip || '127.0.0.1'}</span>
                    </span>
                  </div>

                  {/* 4. Service & Facility */}
                  <div className="w-24 shrink-0 font-mono">
                    <span className="text-xs font-bold text-slate-800 block truncate">{log.service}</span>
                    <span className="text-[10px] text-slate-400 block truncate">{log.facility}</span>
                  </div>

                  {/* 5. Message Payload (break-words, NEVER break-all!) */}
                  <div className="flex-1 min-w-0 pr-2">
                    <p className="text-xs font-mono text-slate-700 break-words leading-relaxed">
                      {log.raw}
                    </p>
                  </div>

                  {/* 6. Cryptographic Hash */}
                  <div className="w-16 shrink-0 text-right font-mono text-[10px] text-slate-400 hidden xl:block">
                    <span className="bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                      {log.hash.slice(0, 6)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Log Inspector Drawer */}
          {selectedLog && (
            <div className="p-3.5 bg-slate-50/90 border-t border-slate-200 text-xs font-mono shrink-0">
              <div className="flex items-center justify-between text-slate-700 pb-2 border-b border-slate-200 mb-2 font-sans">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs">Event #{selectedLog.id} Inspector</span>
                  <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-mono font-bold text-[10px] flex items-center gap-1">
                    <Globe className="w-3 h-3" />
                    {selectedLog.ip || '127.0.0.1'}
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {selectedLog.time} • {selectedLog.service} ({selectedLog.facility})
                  </span>
                </div>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="p-1 rounded hover:bg-slate-200 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
                  title="Close inspector"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="p-2.5 rounded bg-white border border-slate-200 font-mono text-xs text-slate-800 break-words leading-relaxed mb-2 shadow-2xs">
                {selectedLog.raw}
              </div>
              <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono">
                <span className="truncate pr-2">SHA-256 Digest: {selectedLog.hash}</span>
                <span className="text-emerald-700 font-bold shrink-0">✓ Verified Ingestion Record</span>
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
