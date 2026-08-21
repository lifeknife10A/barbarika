export type Severity = 'info' | 'warn' | 'critical' | 'emergency';

export type CertInCategoryCode = 
  | 'i' | 'ii' | 'iii' | 'iv' | 'v' | 'vi' | 'vii' | 'viii' | 'ix' | 'x'
  | 'xi' | 'xii' | 'xiii' | 'xiv' | 'xv' | 'xvi' | 'xvii' | 'xviii' | 'xix' | 'xx';

export interface CertInCategoryInfo {
  code: CertInCategoryCode;
  numeral: string;
  name: string;
  isLiveDetected: boolean;
  detectionRuleId?: string;
  description: string;
}

export interface TelemetryEvent {
  id: string | number;
  event_id: string;
  event_type: string;
  source: string;
  severity: Severity;
  occurred_at: string;
  detected_at: string;
  received_at: string;
  payload: Record<string, any>;
  signature?: string;
  sequence?: number;
  prev_hash?: string;
  record_hash?: string;
  masked_fields?: {
    src_ip?: string;
    username?: string;
    target_path?: string;
  };
}

export type IncidentStatus = 'active' | 'pending_review' | 'confirmed' | 'dismissed' | 'reported';

export interface IncidentTimestamps {
  occurred_at: string;
  detected_at: string;
  received_at: string;
  noticed_at: string;
  confirmed_at?: string;
  reported_at?: string;
}

export interface IncidentRecord {
  id: string;
  category: CertInCategoryCode;
  category_name: string;
  category_numeral: string;
  title: string;
  description: string;
  status: IncidentStatus;
  severity: Severity;
  timestamps: IncidentTimestamps;
  deadline_at: string; // noticed_at + 6 hours
  correlated_event_ids: string[];
  affected_host: string;
  attack_vector: string;
  impact_summary: string;
  mitigation_steps: string[];
  is_candidate_cat_ii?: boolean;
  candidate_reason?: string;
  reviewer_notes?: string;
  reviewer_name?: string;
  rule_id?: string;
  rule_name?: string;
}

export type WatchdogState = 'HEALTHY' | 'TELEMETRY_LOSS' | 'SUSPECTED_HOST_COMPROMISE';

export interface NodeHealth {
  primary_agent: {
    status: 'ONLINE' | 'DEGRADED' | 'DISRUPTED' | 'OFFLINE';
    host: string;
    rss_mb: number;
    inbound_listeners: number; // strictly 0
    egress_mode: 'mTLS_1.3_OUTBOUND_ONLY';
    last_heartbeat_at: string;
    heartbeat_seq: number;
    missed_count: number;
  };
  sentry_host: {
    status: 'ONLINE' | 'ACTIVE' | 'DEGRADED';
    host: string;
    storage_engine: 'SQLite_WAL';
    chain_length: number;
    last_block_hash: string;
    watchdog_state: WatchdogState;
    correlation_window_active: boolean;
    correlation_window_seconds_left: number;
  };
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_name: string;
  user_role: string;
  target_field: string;
  entity_id: string;
  masked_value: string;
  unmasked_value: string;
  reason: string;
  ip_address: string;
}

export interface ProvenanceNode {
  id: string;
  label: string;
  type: 'raw_event' | 'detection_rule' | 'statutory_category' | 'report_field';
  status: 'normal' | 'flagged' | 'matched' | 'generated';
  details: Record<string, any>;
  timestamp?: string;
}

export interface ProvenanceEdge {
  id: string;
  from: string;
  to: string;
  label?: string;
}

export interface VaultBlock {
  sequence: number;
  domain_separator: string;
  prev_hash: string;
  received_at: string;
  event_hash: string;
  block_hash: string;
  verified: boolean;
}

export interface ChainVerificationResult {
  status: 'PASS' | 'FAIL';
  records_count: number;
  valid_signatures: boolean;
  contiguous_sequence: boolean;
  chain_intact: boolean;
  verified_at: string;
  elapsed_ms: number;
  summary: string;
}
