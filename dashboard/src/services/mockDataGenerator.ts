import { TelemetryEvent, IncidentRecord, VaultBlock, NodeHealth } from '../types';

export function createInitialNodeHealth(): NodeHealth {
  return {
    primary_agent: {
      status: 'ONLINE',
      host: 'primary-srv-01.prod.internal',
      rss_mb: 18.4,
      inbound_listeners: 0,
      egress_mode: 'mTLS_1.3_OUTBOUND_ONLY',
      last_heartbeat_at: new Date().toISOString(),
      heartbeat_seq: 1842,
      missed_count: 0,
    },
    sentry_host: {
      status: 'ONLINE',
      host: 'sentry-vault-01.isolated.internal',
      storage_engine: 'SQLite_WAL',
      chain_length: 47,
      last_block_hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      watchdog_state: 'HEALTHY',
      correlation_window_active: false,
      correlation_window_seconds_left: 0,
    },
  };
}

export function createBaselineEvents(): TelemetryEvent[] {
  const now = Date.now();
  return [
    {
      id: 101,
      event_id: 'evt-0190a2b1-001',
      event_type: 'heartbeat',
      source: 'primary-01/daemon',
      severity: 'info',
      occurred_at: new Date(now - 15000).toISOString(),
      detected_at: new Date(now - 14980).toISOString(),
      received_at: new Date(now - 14950).toISOString(),
      sequence: 1840,
      record_hash: '9a31b4028c11e7492a344933924f923b08e2d63f0190a18413b01851adba4901',
      prev_hash: '8f29c1017b00d63819233822813e812a97d1c52e9089907302a907409ca93890',
      signature: 'z0Q8pY7B41xZ0K7wP5L1...ed25519',
      payload: {
        agent_id: 'primary-srv-01',
        boot_id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        agent_health: 'healthy',
        rss_bytes: 19324928,
        inbound_ports: [],
      },
    },
    {
      id: 102,
      event_id: 'evt-0190a2b1-002',
      event_type: 'journald_syslog',
      source: 'primary-01/journald',
      severity: 'info',
      occurred_at: new Date(now - 10000).toISOString(),
      detected_at: new Date(now - 9980).toISOString(),
      received_at: new Date(now - 9950).toISOString(),
      sequence: 1841,
      record_hash: 'b182c5139d22f8503b455044035f034c19f3e74f1201b29524c12962beeb5012',
      prev_hash: '9a31b4028c11e7492a344933924f923b08e2d63f0190a18413b01851adba4901',
      signature: 'm9A7kX6C32wY9J6vO4K0...ed25519',
      payload: {
        unit: 'cron.service',
        message: 'CRON[4912]: (root) CMD (/usr/local/bin/backup-check.sh)',
      },
    },
    {
      id: 103,
      event_id: 'evt-0190a2b1-003',
      event_type: 'heartbeat',
      source: 'primary-01/daemon',
      severity: 'info',
      occurred_at: new Date(now - 5000).toISOString(),
      detected_at: new Date(now - 4980).toISOString(),
      received_at: new Date(now - 4950).toISOString(),
      sequence: 1842,
      record_hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      prev_hash: 'b182c5139d22f8503b455044035f034c19f3e74f1201b29524c12962beeb5012',
      signature: 'v2B4lM8N53zT8Q1uP9R3...ed25519',
      payload: {
        agent_id: 'primary-srv-01',
        boot_id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
        agent_health: 'healthy',
        rss_bytes: 19412096,
        inbound_ports: [],
      },
    }
  ];
}

export function generateCat3Scenario(): { events: TelemetryEvent[]; incident: IncidentRecord } {
  const now = Date.now();
  const occurred = new Date(now - 45000).toISOString();
  const detected = new Date(now - 44500).toISOString();
  const received = new Date(now - 44000).toISOString();
  const noticed = new Date(now - 43800).toISOString();

  const events: TelemetryEvent[] = [
    {
      id: 201,
      event_id: 'evt-cat3-ssh-fail-burst',
      event_type: 'ssh_auth_failure',
      source: 'primary-01/auth.log',
      severity: 'warn',
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      sequence: 1843,
      record_hash: '3f7a192bc58d4e9102ab8472910fae1948bd0192a8374619b02847201948ab12',
      prev_hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      signature: 'k4F9xV2M10wZ3B8rT6P2...ed25519',
      masked_fields: {
        src_ip: '203.0.***.***',
        username: 'ad***',
      },
      payload: {
        src_ip: '203.0.113.87',
        src_port: 48921,
        username: 'admin',
        auth_method: 'password',
        attempts_in_window: 14,
        window_seconds: 30,
        message: 'Failed password for invalid user admin from 203.0.113.87 port 48921 ssh2',
      },
    },
    {
      id: 202,
      event_id: 'evt-cat3-ssh-success',
      event_type: 'ssh_auth_success',
      source: 'primary-01/auth.log',
      severity: 'critical',
      occurred_at: new Date(now - 30000).toISOString(),
      detected_at: new Date(now - 29500).toISOString(),
      received_at: new Date(now - 29000).toISOString(),
      sequence: 1844,
      record_hash: '89bc102938475610293847561029384756102938475610293847561029384756',
      prev_hash: '3f7a192bc58d4e9102ab8472910fae1948bd0192a8374619b02847201948ab12',
      signature: 'q9L2zK4N51xP8V7wM0S4...ed25519',
      masked_fields: {
        src_ip: '203.0.***.***',
        username: 'ad***',
      },
      payload: {
        src_ip: '203.0.113.87',
        username: 'admin',
        auth_method: 'password',
        session_id: 'ssh-sess-9481',
        message: 'Accepted password for admin from 203.0.113.87 port 48921 ssh2',
      },
    },
    {
      id: 203,
      event_id: 'evt-cat3-sudo-escalation',
      event_type: 'sudo_exec',
      source: 'primary-01/auth.log',
      severity: 'critical',
      occurred_at: new Date(now - 20000).toISOString(),
      detected_at: new Date(now - 19500).toISOString(),
      received_at: new Date(now - 19000).toISOString(),
      sequence: 1845,
      record_hash: '9182374619283746192837461928374619283746192837461928374619283746',
      prev_hash: '89bc102938475610293847561029384756102938475610293847561029384756',
      signature: 'j1P8rT3M49wB7X2vK5Q9...ed25519',
      masked_fields: {
        username: 'ad***',
      },
      payload: {
        username: 'admin',
        as_user: 'root',
        command: '/usr/bin/su -',
        tty: 'pts/2',
        pwd: '/home/admin',
        message: 'admin : TTY=pts/2 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/su -',
      },
    },
  ];

  const incident: IncidentRecord = {
    id: 'INC-2026-0819-001',
    category: 'iii',
    category_numeral: 'Category (iii)',
    category_name: 'Unauthorised access of IT systems/data',
    title: 'SSH Brute-Force Credential Stuffing followed by Root Elevation',
    description: '14 failed SSH authentication attempts within 30s followed by successful password login from unrecognized IP 203.0.113.87 and subsequent root privilege elevation via sudo.',
    status: 'active',
    severity: 'critical',
    timestamps: {
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      noticed_at: noticed,
    },
    deadline_at: new Date(new Date(noticed).getTime() + 6 * 3600 * 1000).toISOString(),
    correlated_event_ids: ['evt-cat3-ssh-fail-burst', 'evt-cat3-ssh-success', 'evt-cat3-sudo-escalation'],
    affected_host: 'primary-srv-01.prod.internal',
    attack_vector: 'SSH Credential Stuffing & Privilege Escalation',
    impact_summary: 'Root shell spawned on primary production server. Outbound egress intact; evidence preserved in Sentry WAL vault.',
    mitigation_steps: [
      'Isolate compromised SSH session on primary-srv-01',
      'Revoke admin password and force key-only authentication',
      'Preserve and export tamper-evident Sentry hash chain for CERT-In Annexure I filing',
      'Complete mandatory CERT-In notification within 6-hour statutory deadline',
    ],
    rule_id: 'RULE-CAT-III-SSH-BRUTEFORCE-SUDO',
    rule_name: 'SSH Brute Force + Authentication + Sudo Privilege Elevation',
  };

  return { events, incident };
}

export function generateCat4Scenario(): { events: TelemetryEvent[]; incident: IncidentRecord } {
  const now = Date.now();
  const occurred = new Date(now - 60000).toISOString();
  const detected = new Date(now - 59000).toISOString();
  const received = new Date(now - 58000).toISOString();
  const noticed = new Date(now - 57500).toISOString();

  const events: TelemetryEvent[] = [
    {
      id: 301,
      event_id: 'evt-cat4-nginx-exploit',
      event_type: 'nginx_exploit_probe',
      source: 'primary-01/nginx/access.log',
      severity: 'warn',
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      sequence: 1846,
      record_hash: 'a716253489102938475610293847561029384756102938475610293847561029',
      prev_hash: '9182374619283746192837461928374619283746192837461928374619283746',
      signature: 'w8K2xV1N39zB4M7rT5Q8...ed25519',
      masked_fields: {
        src_ip: '198.51.***.***',
      },
      payload: {
        src_ip: '198.51.100.42',
        method: 'POST',
        uri: '/admin/uploader.php',
        status_code: 200,
        user_agent: 'sqlmap/1.6#stable (https://sqlmap.org)',
        payload_signature: 'multipart/form-data; arbitrary_php_exec',
      },
    },
    {
      id: 302,
      event_id: 'evt-cat4-fsnotify-webroot',
      event_type: 'fsnotify_file_modified',
      source: 'primary-01/fsnotify',
      severity: 'critical',
      occurred_at: new Date(now - 45000).toISOString(),
      detected_at: new Date(now - 44000).toISOString(),
      received_at: new Date(now - 43000).toISOString(),
      sequence: 1847,
      record_hash: 'f928374619283746192837461928374619283746192837461928374619283746',
      prev_hash: 'a716253489102938475610293847561029384756102938475610293847561029',
      signature: 'p3L9zM8N21wT7V4rK0S2...ed25519',
      masked_fields: {
        target_path: '/var/www/html/in***.html',
      },
      payload: {
        path: '/var/www/html/index.html',
        action: 'WRITE_MODIFY',
        old_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        new_sha256: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
        diff_summary: 'Inserted defacement title "HACKED BY TEAM ZERO" and external script href',
      },
    },
  ];

  const incident: IncidentRecord = {
    id: 'INC-2026-0819-002',
    category: 'iv',
    category_numeral: 'Category (iv)',
    category_name: 'Defacement of website or intrusion and unauthorised changes',
    title: 'Nginx Arbitrary File Upload & Web-Root Defacement (/var/www)',
    description: 'Exploit probe POST /admin/uploader.php from 198.51.100.42 correlated with immediate fsnotify file modification on /var/www/html/index.html altering public web content.',
    status: 'active',
    severity: 'critical',
    timestamps: {
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      noticed_at: noticed,
    },
    deadline_at: new Date(new Date(noticed).getTime() + 6 * 3600 * 1000).toISOString(),
    correlated_event_ids: ['evt-cat4-nginx-exploit', 'evt-cat4-fsnotify-webroot'],
    affected_host: 'primary-srv-01.prod.internal',
    attack_vector: 'Web Application Vulnerability + Webroot Tampering',
    impact_summary: 'Public website index altered. Tamper evidence preserved in Sentry vault with fsnotify cryptographic hashes.',
    mitigation_steps: [
      'Revert /var/www/html/index.html from clean immutable backup',
      'Disable vulnerable PHP upload endpoint in Nginx configuration',
      'File Annexure I within 6-hour window citing Category (iv)',
    ],
    rule_id: 'RULE-CAT-IV-WEBROOT-FSNOTIFY-DEFACEMENT',
    rule_name: 'Nginx Exploit Correlated with fsnotify Webroot Defacement',
  };

  return { events, incident };
}

export function generateCat5Scenario(): { events: TelemetryEvent[]; incident: IncidentRecord } {
  const now = Date.now();
  const occurred = new Date(now - 70000).toISOString();
  const detected = new Date(now - 69000).toISOString();
  const received = new Date(now - 68000).toISOString();
  const noticed = new Date(now - 67000).toISOString();

  const events: TelemetryEvent[] = [
    {
      id: 401,
      event_id: 'evt-cat5-rapid-file-burst',
      event_type: 'fsnotify_bulk_modify',
      source: 'primary-01/fsnotify',
      severity: 'critical',
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      sequence: 1848,
      record_hash: 'c837461928374619283746192837461928374619283746192837461928374619',
      prev_hash: 'f928374619283746192837461928374619283746192837461928374619283746',
      signature: 't5M8rB2N19wX4V7zK0Q3...ed25519',
      payload: {
        directory: '/var/data/enterprise_docs',
        files_modified_count: 58,
        time_window_ms: 3200,
        entropy_score: 7.94,
        entropy_indicator: 'HIGH_ENTROPY_ENCRYPTION_DETECTED',
      },
    },
    {
      id: 402,
      event_id: 'evt-cat5-canary-trip',
      event_type: 'canary_file_tampered',
      source: 'primary-01/fsnotify-canary',
      severity: 'emergency',
      occurred_at: new Date(now - 50000).toISOString(),
      detected_at: new Date(now - 49000).toISOString(),
      received_at: new Date(now - 48000).toISOString(),
      sequence: 1849,
      record_hash: 'd928374619283746192837461928374619283746192837461928374619283746',
      prev_hash: 'c837461928374619283746192837461928374619283746192837461928374619',
      signature: 'b7V4rK0S2p3L9zM8N21w...ed25519',
      payload: {
        canary_path: '/var/data/.canary_document_do_not_edit.docx',
        action: 'RENAMED_TO_LOCKED',
        new_extension: '.locked',
        ransom_note_found: '/var/data/README_TO_DECRYPT.txt',
      },
    },
  ];

  const incident: IncidentRecord = {
    id: 'INC-2026-0819-003',
    category: 'v',
    category_numeral: 'Category (v)',
    category_name: 'Malicious code attacks (Virus / Trojan / Ransomware)',
    title: 'Ransomware High-Entropy Bulk Encryption & Canary Trap Triggered',
    description: 'Rapid modification of 58 files within 3.2s with entropy score 7.94 followed by tampering and renaming of tripwire canary document .canary_document_do_not_edit.docx to .locked.',
    status: 'active',
    severity: 'emergency',
    timestamps: {
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      noticed_at: noticed,
    },
    deadline_at: new Date(new Date(noticed).getTime() + 6 * 3600 * 1000).toISOString(),
    correlated_event_ids: ['evt-cat5-rapid-file-burst', 'evt-cat5-canary-trip'],
    affected_host: 'primary-srv-01.prod.internal',
    attack_vector: 'Ransomware / Malicious Encryption Binary',
    impact_summary: 'User data directory encryption attempted. Tripwire canary halted lateral movement; prior signed logs preserved off-host on Sentry.',
    mitigation_steps: [
      'Quarantine process PID responsible for canary alteration',
      'Retain isolated Sentry logs for forensic timestamp chain verification',
      'Generate and file CERT-In Category (v) incident disclosure before 6-hour deadline',
    ],
    rule_id: 'RULE-CAT-V-RANSOMWARE-CANARY-TRIP',
    rule_name: 'Rapid Multi-File Encryption + Canary Tripwire Trigger',
  };

  return { events, incident };
}

export function generateCat2CandidateScenario(): { events: TelemetryEvent[]; incident: IncidentRecord; nodeHealth: NodeHealth } {
  const now = Date.now();
  const occurred = new Date(now - 130000).toISOString();
  const detected = new Date(now - 128000).toISOString();
  const received = new Date(now - 127000).toISOString();
  const noticed = new Date(now - 20000).toISOString();

  const events: TelemetryEvent[] = [
    {
      id: 501,
      event_id: 'evt-cat2-intrusion-probe',
      event_type: 'ssh_auth_failure',
      source: 'primary-01/auth.log',
      severity: 'critical',
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      sequence: 1850,
      record_hash: 'e128374619283746192837461928374619283746192837461928374619283746',
      prev_hash: 'd928374619283746192837461928374619283746192837461928374619283746',
      signature: 'z8P4vK1M39wB7X2vK5Q9...ed25519',
      masked_fields: {
        src_ip: '203.0.***.***',
      },
      payload: {
        src_ip: '203.0.113.99',
        username: 'root',
        message: 'Repeated privileged intrusion attempts detected',
      },
    },
    {
      id: 502,
      event_id: 'evt-cat2-telemetry-loss',
      event_type: 'watchdog_telemetry_loss',
      source: 'sentry-vault-01/watchdog',
      severity: 'emergency',
      occurred_at: new Date(now - 25000).toISOString(),
      detected_at: new Date(now - 22000).toISOString(),
      received_at: new Date(now - 20000).toISOString(),
      sequence: 1851,
      record_hash: 'f228374619283746192837461928374619283746192837461928374619283746',
      prev_hash: 'e128374619283746192837461928374619283746192837461928374619283746',
      payload: {
        reason: '3 consecutive missed heartbeats (15s flatline)',
        correlated_with_intrusion: true,
        correlation_window_sec: 120,
        candidate_category: 'ii',
        requires_human_confirmation: true,
      },
    },
  ];

  const incident: IncidentRecord = {
    id: 'INC-2026-0819-004-CANDIDATE',
    category: 'ii',
    category_numeral: 'Candidate Category (ii)',
    category_name: 'Compromise of critical systems/information',
    title: 'Adversarial Host Disruption / Dead Man Switch (Candidate Category ii)',
    description: 'Telemetry loss triggered after 3 missed heartbeats (15s) immediately following high-confidence intrusion activity within 120s correlation window. Per AGENTS.md Rule 2, requires mandatory human confirmation before official escalation.',
    status: 'pending_review',
    severity: 'emergency',
    timestamps: {
      occurred_at: occurred,
      detected_at: detected,
      received_at: received,
      noticed_at: noticed,
    },
    deadline_at: new Date(new Date(noticed).getTime() + 6 * 3600 * 1000).toISOString(),
    correlated_event_ids: ['evt-cat2-intrusion-probe', 'evt-cat2-telemetry-loss'],
    affected_host: 'primary-srv-01.prod.internal',
    attack_vector: 'Suspected Adversarial Disruption / Process Termination',
    impact_summary: 'Primary server telemetry terminated post-attack. Sentry hash chain remains untampered and verified off-host.',
    mitigation_steps: [
      'Review correlation window evidence and assess physical/network host state',
      'Confirm incident in CISO dashboard to promote Candidate Cat (ii) to confirmed statutory report',
      'Or dismiss as benign operational network loss if scheduled maintenance',
    ],
    is_candidate_cat_ii: true,
    candidate_reason: 'Heartbeat flatline correlated with active intrusion probe within 120s window.',
    rule_id: 'RULE-WATCHDOG-CORRELATED-DISRUPTION',
    rule_name: 'Watchdog Dead Man Switch Correlated Host Disruption',
  };

  const nodeHealth: NodeHealth = {
    primary_agent: {
      status: 'DISRUPTED',
      host: 'primary-srv-01.prod.internal',
      rss_mb: 0,
      inbound_listeners: 0,
      egress_mode: 'mTLS_1.3_OUTBOUND_ONLY',
      last_heartbeat_at: new Date(now - 25000).toISOString(),
      heartbeat_seq: 1849,
      missed_count: 5,
    },
    sentry_host: {
      status: 'ACTIVE',
      host: 'sentry-vault-01.isolated.internal',
      storage_engine: 'SQLite_WAL',
      chain_length: 51,
      last_block_hash: 'f228374619283746192837461928374619283746192837461928374619283746',
      watchdog_state: 'SUSPECTED_HOST_COMPROMISE',
      correlation_window_active: true,
      correlation_window_seconds_left: 95,
    },
  };

  return { events, incident, nodeHealth };
}
