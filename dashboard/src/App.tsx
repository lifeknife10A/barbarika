import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { DeadlineClock } from './components/DeadlineClock';
import { WatchdogMonitor } from './components/WatchdogMonitor';
import { ProvenanceGraph } from './components/ProvenanceGraph';
import { EvidenceVault } from './components/EvidenceVault';
import { LiveEventFeed } from './components/LiveEventFeed';
import { TaxonomyView } from './components/TaxonomyView';
import { AuditTrailView } from './components/AuditTrailView';
import { DemoScenarios } from './components/DemoScenarios';
import { ComplianceDraftModal } from './components/ComplianceDraftModal';
import { HumanReviewModal } from './components/HumanReviewModal';
import { TelemetryEvent, IncidentRecord, NodeHealth } from './types';
import { realtimeService } from './services/sseClient';
import { AuditLogger } from './services/auditLogger';
import {
  createBaselineEvents,
  createInitialNodeHealth,
  generateCat3Scenario,
  generateCat4Scenario,
  generateCat5Scenario,
  generateCat2CandidateScenario,
} from './services/mockDataGenerator';

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'events' | 'provenance' | 'vault' | 'audit' | 'categories'>('overview');
  const [events, setEvents] = useState<TelemetryEvent[]>(createBaselineEvents());
  const [currentIncident, setCurrentIncident] = useState<IncidentRecord | null>(null);
  const [nodeHealth, setNodeHealth] = useState<NodeHealth>(createInitialNodeHealth());
  const [activeScenarioName, setActiveScenarioName] = useState<string | null>(null);

  // Modals state
  const [isDraftModalOpen, setIsDraftModalOpen] = useState(false);
  const [isReviewModalOpen, setIsReviewModalOpen] = useState(false);
  const [unmaskData, setUnmaskData] = useState<{ field: string; entityId: string; maskedVal: string; realVal: string } | null>(null);
  const [auditCount, setAuditCount] = useState(AuditLogger.getLogs().length);

  // Realtime subscriptions
  useEffect(() => {
    const unsubHealth = realtimeService.subscribeHealth((h) => setNodeHealth(h));
    const unsubEvent = realtimeService.subscribeEvents((evt) => {
      setEvents((prev) => [evt, ...prev.slice(0, 150)]);
    });
    const unsubIncident = realtimeService.subscribeIncidents((inc) => {
      setCurrentIncident(inc);
    });
    const unsubAudit = AuditLogger.subscribe((logs) => setAuditCount(logs.length));

    return () => {
      unsubHealth();
      unsubEvent();
      unsubIncident();
      unsubAudit();
    };
  }, []);

  // Demo Scenarios Handlers
  const handleTriggerCat3 = () => {
    const { events: cat3Events, incident } = generateCat3Scenario();
    setEvents((prev) => [...cat3Events, ...prev]);
    setCurrentIncident(incident);
    setActiveScenarioName('Cat (iii) SSH Brute-Force + Sudo Elevation');
    setActiveTab('overview');
  };

  const handleTriggerCat4 = () => {
    const { events: cat4Events, incident } = generateCat4Scenario();
    setEvents((prev) => [...cat4Events, ...prev]);
    setCurrentIncident(incident);
    setActiveScenarioName('Cat (iv) Web-Root Defacement');
    setActiveTab('overview');
  };

  const handleTriggerCat5 = () => {
    const { events: cat5Events, incident } = generateCat5Scenario();
    setEvents((prev) => [...cat5Events, ...prev]);
    setCurrentIncident(incident);
    setActiveScenarioName('Cat (v) Ransomware & Canary Trip');
    setActiveTab('overview');
  };

  const handleTriggerCat2 = () => {
    const { events: cat2Events, incident, nodeHealth: disruptedHealth } = generateCat2CandidateScenario();
    setEvents((prev) => [...cat2Events, ...prev]);
    setCurrentIncident(incident);
    setNodeHealth(disruptedHealth);
    realtimeService.setNodeHealth(disruptedHealth);
    setActiveScenarioName('Candidate Cat (ii) Dead Man Switch');
    setIsReviewModalOpen(true);
    setActiveTab('overview');
  };

  const handleResetClean = () => {
    const cleanHealth = createInitialNodeHealth();
    setNodeHealth(cleanHealth);
    realtimeService.setNodeHealth(cleanHealth);
    setEvents(createBaselineEvents());
    setCurrentIncident(null);
    setActiveScenarioName(null);
  };

  // Review confirmation
  const handleConfirmIncident = (notes: string) => {
    if (currentIncident) {
      const confirmed: IncidentRecord = {
        ...currentIncident,
        status: 'confirmed',
        reviewer_notes: notes,
        reviewer_name: 'Nandini Chitlangia (CISO)',
        timestamps: {
          ...currentIncident.timestamps,
          confirmed_at: new Date().toISOString(),
        },
      };
      setCurrentIncident(confirmed);
    }
    setIsReviewModalOpen(false);
  };

  const handleDismissIncident = (reason: string) => {
    if (currentIncident) {
      setCurrentIncident({
        ...currentIncident,
        status: 'dismissed',
        reviewer_notes: reason,
      });
    }
    setIsReviewModalOpen(false);
  };

  const handleOpenUnmask = (field: string, entityId: string, maskedVal: string, realVal: string) => {
    setUnmaskData({ field, entityId, maskedVal, realVal });
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col cyber-grid">
      
      {/* Top Navigation */}
      <Header
        health={nodeHealth}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAudit={() => setActiveTab('audit')}
        unmaskAuditCount={auditCount}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Stage Demo Controller */}
        <DemoScenarios
          onTriggerCat3={handleTriggerCat3}
          onTriggerCat4={handleTriggerCat4}
          onTriggerCat5={handleTriggerCat5}
          onTriggerCat2={handleTriggerCat2}
          onResetClean={handleResetClean}
          activeScenarioName={activeScenarioName}
        />

        {/* Tab Views */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* 6-Hour Statutory Deadline Clock */}
            <DeadlineClock
              incident={currentIncident}
              onOpenDraft={() => setIsDraftModalOpen(true)}
              onOpenReview={() => setIsReviewModalOpen(true)}
            />

            {/* Inverted Watchdog & Host Health */}
            <WatchdogMonitor health={nodeHealth} />

            {/* Provenance Graph */}
            <ProvenanceGraph
              incident={currentIncident}
              events={events}
              onOpenUnmask={handleOpenUnmask}
            />

            {/* Live Feed Preview */}
            <LiveEventFeed
              events={events}
              onOpenUnmask={handleOpenUnmask}
            />
          </div>
        )}

        {activeTab === 'provenance' && (
          <ProvenanceGraph
            incident={currentIncident}
            events={events}
            onOpenUnmask={handleOpenUnmask}
          />
        )}

        {activeTab === 'vault' && (
          <EvidenceVault health={nodeHealth} />
        )}

        {activeTab === 'events' && (
          <LiveEventFeed
            events={events}
            onOpenUnmask={handleOpenUnmask}
          />
        )}

        {activeTab === 'categories' && (
          <TaxonomyView />
        )}

        {activeTab === 'audit' && (
          <AuditTrailView />
        )}

      </main>

      {/* Footer */}
      <footer className="w-full border-t border-cyber-border bg-[#070a10] py-4 text-xs text-slate-500 font-mono-code">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-bold">Barbarika Platform</span>
            <span>•</span>
            <span>SIH 2026 Submission (Team Barbarika, NMIMS MPSTME)</span>
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span>Theme: Blockchain & Cybersecurity</span>
            <span>•</span>
            <span>IT Act Sec 70B(6) Assisted Readiness</span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <ComplianceDraftModal
        isOpen={isDraftModalOpen}
        onClose={() => setIsDraftModalOpen(false)}
        incident={currentIncident}
      />

      <HumanReviewModal
        isOpen={isReviewModalOpen}
        onClose={() => setIsReviewModalOpen(false)}
        incident={currentIncident}
        onConfirmIncident={handleConfirmIncident}
        onDismissIncident={handleDismissIncident}
        unmaskData={unmaskData}
        onClearUnmaskData={() => setUnmaskData(null)}
      />

    </div>
  );
}

export default App;
