import { TelemetryEvent, IncidentRecord, NodeHealth } from '../types';
import { createInitialNodeHealth } from './mockDataGenerator';

export type EventCallback = (event: TelemetryEvent) => void;
export type IncidentCallback = (incident: IncidentRecord) => void;
export type HealthCallback = (health: NodeHealth) => void;

class RealtimeService {
  private eventSource: EventSource | null = null;
  private eventListeners: Set<EventCallback> = new Set();
  private incidentListeners: Set<IncidentCallback> = new Set();
  private healthListeners: Set<HealthCallback> = new Set();
  private isConnected = false;
  private isSimulatedMode = true;
  private simulationTimer: any = null;
  private pollTimer: any = null;
  private heartbeatSeq = 1842;
  private currentHealth: NodeHealth = createInitialNodeHealth();

  constructor() {
    // Start simulation heartbeats for demo resilience, attempt SSE, fallback to polling if SSE is disconnected
    this.startSimulationHeartbeats();
    this.tryConnectSSE();
  }

  public tryConnectSSE(endpoint = '/events/stream') {
    if (typeof window === 'undefined') return;

    try {
      if (this.eventSource) {
        this.eventSource.close();
      }

      this.eventSource = new EventSource(endpoint);

      this.eventSource.onopen = () => {
        this.isConnected = true;
        this.isSimulatedMode = false;
        this.stopPolling();
        console.log('[Barbarika SSE] Connected to live Sentry event stream');
      };

      this.eventSource.addEventListener('telemetry', (e: MessageEvent) => {
        try {
          const parsed: TelemetryEvent = JSON.parse(e.data);
          this.notifyEvent(parsed);
        } catch (err) {
          console.warn('[Barbarika SSE] Failed to parse event payload', err);
        }
      });

      this.eventSource.addEventListener('incident', (e: MessageEvent) => {
        try {
          const parsed: IncidentRecord = JSON.parse(e.data);
          this.notifyIncident(parsed);
        } catch (err) {
          console.warn('[Barbarika SSE] Failed to parse incident', err);
        }
      });

      this.eventSource.addEventListener('heartbeat', (e: MessageEvent) => {
        try {
          const parsed: NodeHealth = JSON.parse(e.data);
          this.currentHealth = parsed;
          this.notifyHealth(parsed);
        } catch (err) {
          console.warn('[Barbarika SSE] Failed to parse heartbeat', err);
        }
      });

      this.eventSource.onerror = () => {
        this.isConnected = false;
        console.log('[Barbarika SSE] SSE disconnected, activating fallback polling...');
        this.startFallbackPolling();
      };
    } catch (e) {
      console.log('[Barbarika SSE] SSE endpoint unreachable, starting fallback polling.');
      this.startFallbackPolling();
    }
  }

  private startFallbackPolling() {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(async () => {
      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          const data = await res.json();
          if (data && data.status === 'ok') {
            this.currentHealth = {
              ...this.currentHealth,
              sentry_host: {
                ...this.currentHealth.sentry_host,
                chain_length: data.events || this.currentHealth.sentry_host.chain_length,
              }
            };
            this.notifyHealth(this.currentHealth);
          }
        }
      } catch (err) {
        // Standalone mode: simulated heartbeats continue uninterrupted
      }
    }, 4000);
  }

  private stopPolling() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private startSimulationHeartbeats() {
    if (this.simulationTimer) clearInterval(this.simulationTimer);

    this.simulationTimer = setInterval(() => {
      if (this.currentHealth.primary_agent.status === 'DISRUPTED') {
        // Increment missed count if disrupted
        this.currentHealth.primary_agent.missed_count += 1;
        this.notifyHealth({ ...this.currentHealth });
        return;
      }

      this.heartbeatSeq += 1;
      const now = new Date().toISOString();

      this.currentHealth = {
        ...this.currentHealth,
        primary_agent: {
          ...this.currentHealth.primary_agent,
          last_heartbeat_at: now,
          heartbeat_seq: this.heartbeatSeq,
          missed_count: 0,
        },
        sentry_host: {
          ...this.currentHealth.sentry_host,
          chain_length: this.currentHealth.sentry_host.chain_length + 1,
        }
      };

      this.notifyHealth(this.currentHealth);

      // Emit heartbeat telemetry event
      const hbEvent: TelemetryEvent = {
        id: `hb-${this.heartbeatSeq}`,
        event_id: `evt-hb-${this.heartbeatSeq}`,
        event_type: 'heartbeat',
        source: 'primary-01/daemon',
        severity: 'info',
        occurred_at: now,
        detected_at: now,
        received_at: now,
        sequence: this.heartbeatSeq,
        record_hash: `${Math.random().toString(16).substring(2)}${Math.random().toString(16).substring(2)}`,
        prev_hash: this.currentHealth.sentry_host.last_block_hash,
        signature: 'ed25519_sig_valid_ok',
        payload: {
          agent_id: 'primary-srv-01',
          agent_health: 'healthy',
          rss_bytes: 19324928 + Math.floor(Math.random() * 80000),
          inbound_listeners: 0,
        }
      };

      this.notifyEvent(hbEvent);
    }, 5000);
  }

  public setNodeHealth(health: NodeHealth) {
    this.currentHealth = health;
    this.notifyHealth(health);
  }

  public getNodeHealth(): NodeHealth {
    return this.currentHealth;
  }

  public subscribeEvents(cb: EventCallback): () => void {
    this.eventListeners.add(cb);
    return () => this.eventListeners.delete(cb);
  }

  public subscribeIncidents(cb: IncidentCallback): () => void {
    this.incidentListeners.add(cb);
    return () => this.incidentListeners.delete(cb);
  }

  public subscribeHealth(cb: HealthCallback): () => void {
    this.healthListeners.add(cb);
    cb(this.currentHealth);
    return () => this.healthListeners.delete(cb);
  }

  public notifyEvent(event: TelemetryEvent) {
    this.eventListeners.forEach(cb => cb(event));
  }

  public notifyIncident(incident: IncidentRecord) {
    this.incidentListeners.forEach(cb => cb(incident));
  }

  public notifyHealth(health: NodeHealth) {
    this.healthListeners.forEach(cb => cb(health));
  }
}

export const realtimeService = new RealtimeService();
