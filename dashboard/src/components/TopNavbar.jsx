import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Clock, 
  FileText, 
  Eye, 
  EyeOff, 
  Menu, 
  X, 
  Activity, 
  GitBranch, 
  HardDrive, 
  Server,
  LayoutDashboard,
  AlertTriangle,
  Lock,
  Cpu,
  UserCheck
} from 'lucide-react';

export default function TopNavbar({ 
  isPiiMasked,
  onToggleMask,
  onOpenReport
}) {
  return (
    <header className="border-b border-slate-200/90 bg-white/95 backdrop-blur-md px-4 py-2.5 shrink-0 z-30 shadow-xs text-slate-800">
      <div className="flex items-center justify-between gap-3">
        
        {/* Brand (Kept) */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="relative">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-600 to-indigo-800 text-white flex items-center justify-center font-bold shadow-xs">
              <Shield className="w-4 h-4 text-white" />
            </div>
          </div>

          <div>
            <h1 className="text-base font-bold text-slate-900 tracking-wider uppercase font-sans">
              BARBARIKA
            </h1>
          </div>
        </div>

        {/* Right Action Controls: Clean and Minimal */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-sans font-semibold bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs transition-all cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-indigo-100" />
            <span>Incident Report</span>
          </button>
        </div>

      </div>
    </header>
  );
}

