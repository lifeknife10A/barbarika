// ─────────────────────────────────────────────────────────────────────────────
// SINGLE SOURCE OF TRUTH for everything the dashboard renders.
//
// Nothing in the UI should hard-code a display string. Every label, metric,
// OS name, host name, status and series lives here, so wiring real telemetry
// later is just a matter of replacing this object's values (or feeding it from
// the Sentry SSE stream) — the components never change.
//
// While we build visuals this is dummy data; the SHAPE is the contract.
// ─────────────────────────────────────────────────────────────────────────────

export const systemModel = {
  // Who is being watched, and by what. Names are derived, never stamped in JSX.
  // Display convention (placeholder — to finalise): "<host-key> @ <sentry-key>".
  identity: {
    target: {
      key: 'primary-srv-01',
      hostname: 'prod-fin-vps01.msme-internal.net',
      os: 'Ubuntu 24.04 LTS',
      kernel: '6.8.0-31-generic',
      role: 'Monitored production host',
    },
    sentry: {
      key: 'sentry-vault-01',
      enclave: 'Isolated black-box micro-VM',
      engine: 'SQLite 3.45 · WAL',
    },
  },

  // ── System (agent host) health ──────────────────────────────────────────────
  // `state` drives a small dot only (no wordy badge). tiles render generically.
  systemHealth: {
    state: 'healthy', // healthy | warning | critical
    tiles: [
      { id: 'cpu',    icon: 'cpu',    label: 'CPU Load',  value: '24',     unit: '%',  meta: '12 cores · load 0.42',        fill: 24,  accent: '#2a78d6' },
      { id: 'memory', icon: 'memory', label: 'Memory',    value: '4.2',    unit: 'GB', meta: 'of 16 GB · agent RSS 41 MB',  fill: 26,  accent: '#4a3aa7' },
      { id: 'daemon', icon: 'daemon', label: 'Go Daemon', value: 'Active', unit: '',   meta: 'Ed25519 · egress-only mTLS',  fill: 100, accent: '#1baf7a' },
    ],
  },

  // ── Sentry (vault) health ───────────────────────────────────────────────────
  sentryHealth: {
    state: 'healthy',
    tiles: [
      { id: 'watchdog', icon: 'watchdog', label: 'Watchdog',      value: 'T-03s', unit: '',       meta: '5 s window · pulse OK',      fill: 60,  accent: '#eb6834' },
      { id: 'vault',    icon: 'vault',    label: 'Vault Storage',  value: '17.8',  unit: 'MB',     meta: 'WAL · append-only',          fill: 42,  accent: '#e0a100' },
      { id: 'chain',    icon: 'chain',    label: 'Hash Chain',     value: '47',    unit: 'blocks', meta: 'SHA-256 · 100% intact',      fill: 100, accent: '#008300' },
    ],
  },

  // ── Events per minute (idle = near-zero; that is correct, no events yet) ──────
  // The chart auto-scales to the data so idle traffic is still legible; the spike
  // threshold is shown as a caption, not a forced axis bound.
  epm: {
    current: 3,
    unit: 'EPM',
    spikeThreshold: 3200,
    // 30 one-minute buckets, oldest → newest. Quiet host.
    history: [2, 1, 3, 2, 4, 2, 1, 2, 3, 5, 2, 1, 0, 2, 3, 1, 2, 4, 2, 1, 3, 2, 2, 5, 3, 2, 1, 2, 4, 3],
    spanLabel: 'last 30 min',
  },

  // (The secondary chart under EPM is the live "events by severity" mix — it is
  //  aggregated from `logs` at render time, so there is no separate data source
  //  to keep here: real when connected, the mock feed below when offline.)

  // ── Detection incidents (offline fallback). Live path fills this from
  //    GET /incidents + the SSE `incident` stream. eventIds tie each incident
  //    back to the log rows below, which the feed then flags by category. ──────
  incidents: [
    {
      id: 'mock-iii-1',
      category: 'iii',
      ruleTitle: 'SSH brute force, successful authentication, then privileged sudo',
      ruleId: 'afe8cbd2',
      eventIds: [1055, 1054, 1045, 1047, 1048],
      time: '18:13:48',
    },
  ],

  // ── Incoming log feed (dummy rows; the container is scrollable + minimal) ─────
  // level ∈ info | notice | warn | critical  (drives a single dot colour)
  logs: [
    { id: 1058, time: '18:14:41', level: 'info',     source: '203.0.113.19',  service: 'nginx',   message: "POST /api/v1/telemetry HTTP/1.1 200 client=203.0.113.19 bytes=1420", digest: 'e48109' },
    { id: 1057, time: '18:14:39', level: 'notice',   source: '127.0.0.1',     service: 'systemd', message: 'barbarika-sentry.service: sliding heartbeat seq #1842', digest: 'c20491' },
    { id: 1056, time: '18:14:31', level: 'info',     source: '10.0.4.18',     service: 'nginx',   message: "GET /api/v1/health HTTP/1.1 200 0.002s ua='Barbarika-Probe/1.4'", digest: 'b8971f' },
    { id: 1055, time: '18:14:22', level: 'warn',     source: '198.51.100.74', service: 'sshd',    message: 'Failed password for invalid user «account» from «ip» port 43210', digest: 'd94103' },
    { id: 1054, time: '18:14:20', level: 'warn',     source: '198.51.100.74', service: 'sshd',    message: 'Failed password for invalid user «account» from «ip» port 43208', digest: 'a71f5c' },
    { id: 1053, time: '18:14:15', level: 'info',     source: '127.0.0.1',     service: 'kernel',  message: 'audit: fim watch armed on /var/www, /srv/data', digest: '9c02aa' },
    { id: 1052, time: '18:14:08', level: 'info',     source: '10.0.4.18',     service: 'nginx',   message: "GET /assets/app.js HTTP/1.1 200 0.001s", digest: '77e310' },
    { id: 1051, time: '18:14:02', level: 'info',     source: '192.168.10.45', service: 'sshd',    message: 'Connection established from «ip» port 54822 [user=deploy-svc]', digest: '7a52e6' },
    { id: 1050, time: '18:13:58', level: 'notice',   source: '127.0.0.1',     service: 'systemd', message: 'barbarika-agent.service: egress mTLS handshake ok', digest: '5510bd' },
    { id: 1049, time: '18:13:51', level: 'info',     source: '10.0.4.18',     service: 'nginx',   message: "GET /api/v1/incidents HTTP/1.1 200 0.004s", digest: '41aa02' },
    { id: 1048, time: '18:13:44', level: 'critical', source: '198.51.100.74', service: 'sudo',    message: '«account» : COMMAND=/bin/bash — privileged shell (rule iii)', digest: 'f0091a' },
    { id: 1047, time: '18:13:40', level: 'warn',     source: '198.51.100.74', service: 'sshd',    message: 'Accepted password for «account» from «ip» port 43222', digest: 'be7741' },
    { id: 1046, time: '18:13:31', level: 'info',     source: '203.0.113.19',  service: 'nginx',   message: "GET /shop/index.php?category=1 HTTP/1.1 200 4213", digest: '3190bd' },
    { id: 1045, time: '18:13:22', level: 'warn',     source: '198.51.100.74', service: 'sshd',    message: 'Failed password for invalid user «account» from «ip» port 43204', digest: '220194' },
    { id: 1044, time: '18:13:15', level: 'info',     source: '127.0.0.1',     service: 'kernel',  message: 'audit: hash-chain block #47 sealed sha256=…a7e0b3', digest: 'c4d221' },
    { id: 1043, time: '18:13:08', level: 'info',     source: '10.0.4.18',     service: 'nginx',   message: "GET /favicon.ico HTTP/1.1 304 0.000s", digest: '08f7aa' },
    { id: 1042, time: '18:13:02', level: 'notice',   source: '127.0.0.1',     service: 'systemd', message: 'barbarika-sentry.service: WAL checkpoint (truncate) ok', digest: '9be004' },
    { id: 1041, time: '18:12:55', level: 'info',     source: '192.168.10.45', service: 'sshd',    message: 'pam_unix(sshd:session): session opened for user deploy-svc', digest: '771a02' },
  ],
};

// Convenience: the derived identity label (single place to change the format).
export const identityLabel = (m) => `${m.identity.target.key} @ ${m.identity.sentry.key}`;
