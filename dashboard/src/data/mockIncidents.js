// Barbarika SIEM & Incident Provenance Telemetry Dataset
// Matches official CERT-In Annexure I statutory guidelines & 36-Hour Hackathon Blueprint verbatim

export const INITIAL_NODES = {
  primaryServer: {
    id: "primary-srv-01",
    hostname: "prod-fin-vps01.msme-internal.net",
    os: "Ubuntu 24.04 LTS (Kernel 6.8.0-31-generic)",
    ip: "192.168.10.45",
    publicIp: "203.0.113.19",
    agentVersion: "barbarika-daemon-v1.4.2-go",
    ramUsageMB: 12.4,
    cpuPercent: 1.8,
    outboundProtocol: "mTLS 1.3 (Strict Outbound Only)",
    inboundPortsOpen: 0,
    status: "HEALTHY", // HEALTHY | WARNING | COMPROMISED | FLATLINED
    lastHeartbeat: new Date().toISOString(),
    bootId: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    sequence: 1842,
  },
  sentryVault: {
    id: "sentry-vault-01",
    enclaveName: "Black-Box Sentry Micro-VM",
    ip: "10.240.0.12",
    storageEngine: "SQLite 3.45 (WAL Mode) + Append-Only NDJSON",
    hashAlgorithm: "SHA-256 Recursive Chaining",
    status: "ARMED",
    recordsIndexed: 47,
    tamperDetected: false,
    watchdogState: "WATCHING", // WATCHING | MISSED_1 | MISSED_2 | TELEMETRY_LOSS | SUSPECTED_COMPROMISE
    missedHeartbeats: 0,
    deadManSwitchArmed: true,
  }
};

// 3 Focused Live-Demo Detection Paths (Blueprint Section 4)
export const DETECTION_PATHS = {
  CAT3: {
    id: "PATH-1-CAT3",
    category: "Category III",
    categoryTitle: "Unauthorized Access / Compromise of Critical Systems",
    statutoryRef: "CERT-In Dir. 2022 Para 5(i) - Cat III",
    ruleId: "SIGMA-CAT3-001",
    ruleName: "High-Frequency SSH Authentication Failures followed by Root Privilege Escalation",
    severity: "CRITICAL",
    conditions: "count(failed_ssh_attempts) >= 10 within 60s AND event(sudo_su_bash) == true",
    mitreTechniques: ["T1110.001 - Password Brute Force", "T1548.003 - Sudo and Sudo Caching"],
    confidenceScore: 0.99,
    attackerIp: "198.51.100.74",
    impactDescription: "Compromise of primary production host credentials via external SSH dictionary spray resulting in root execution.",
    events: [
      { id: 1021, time: "12:08:44", source: "auth.log", facility: "sshd", severity: "INFO", raw: "sshd[2891]: Connection from 198.51.100.74 port 54210 on 192.168.10.45 port 22", redactedRaw: "sshd[2891]: Connection from [EXT_IP_REDACTED] port 54210 on [INT_NET_REDACTED] port 22", hash: "b8971f...40c03" },
      { id: 1022, time: "12:08:45", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2891]: Failed password for invalid user admin from 198.51.100.74 port 54210", redactedRaw: "sshd[2891]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "c20491...a1105" },
      { id: 1023, time: "12:08:48", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2895]: Failed password for invalid user root from 198.51.100.74 port 54212", redactedRaw: "sshd[2895]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "d94103...fe229" },
      { id: 1024, time: "12:08:51", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2901]: Failed password for invalid user operator from 198.51.100.74 port 54214", redactedRaw: "sshd[2901]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "e51928...410b2" },
      { id: 1025, time: "12:08:54", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2908]: Failed password for invalid user deploy from 198.51.100.74 port 54216", redactedRaw: "sshd[2908]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "f01948...918ce" },
      { id: 1026, time: "12:08:57", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2914]: Failed password for invalid user test from 198.51.100.74 port 54218", redactedRaw: "sshd[2914]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "11904a...3190b" },
      { id: 1027, time: "12:09:00", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2920]: Failed password for invalid user guest from 198.51.100.74 port 54220", redactedRaw: "sshd[2920]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "220194...4281a" },
      { id: 1028, time: "12:09:03", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2925]: Failed password for invalid user dbadmin from 198.51.100.74 port 54222", redactedRaw: "sshd[2925]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "33109a...5392b" },
      { id: 1029, time: "12:09:06", source: "auth.log", facility: "sshd", severity: "WARN", raw: "sshd[2930]: Failed password for invalid user backup from 198.51.100.74 port 54224", redactedRaw: "sshd[2930]: Failed password for invalid user [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "44210b...6403c" },
      { id: 1030, time: "12:09:09", source: "auth.log", facility: "sshd", severity: "ALERT", raw: "sshd[2935]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.74", redactedRaw: "sshd[2935]: PAM 2 more authentication failures; rhost=[EXT_IP_REDACTED]", hash: "55321c...7514d" },
      { id: 1031, time: "12:09:12", source: "auth.log", facility: "sshd", severity: "CRITICAL", raw: "sshd[2940]: Accepted password for msme_admin from 198.51.100.74 port 54228 ssh2", redactedRaw: "sshd[2940]: Accepted password for [USER_REDACTED] from [EXT_IP_REDACTED]", hash: "a123f4...ef1234" },
      { id: 1032, time: "12:09:18", source: "auth.log", facility: "sudo", severity: "CRITICAL", raw: "sudo[3010]: msme_admin : TTY=pts/0 ; PWD=/home/msme_admin ; USER=root ; COMMAND=/bin/bash", redactedRaw: "sudo[3010]: [USER_REDACTED] : USER=root ; COMMAND=/bin/bash", hash: "5f891b...8e9f01" },
      { id: 1033, time: "12:09:42", source: "journald", facility: "systemd", severity: "CRITICAL", raw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", redactedRaw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", hash: "98e72a...9d8e7f" }
    ]
  },
  CAT10: {
    id: "PATH-2-CAT10",
    category: "Category X",
    categoryTitle: "Attacks on Critical Applications & Web Services",
    statutoryRef: "CERT-In Dir. 2022 Para 5(i) - Cat X",
    ruleId: "SIGMA-CAT10-002",
    ruleName: "Dot-Env Credential Probing Followed by Docroot File Integrity Tampering",
    severity: "HIGH",
    conditions: "http.uri matches '/.env' OR '/wp-login.php' AND response.status == 200 AND file_integrity.docroot == altered",
    mitreTechniques: ["T1190 - Exploit Public-Facing Application", "T1552 - Unsecured Credentials", "T1505.003 - Web Shell"],
    confidenceScore: 0.95,
    attackerIp: "203.0.113.188",
    impactDescription: "Exploitation of web server endpoint leading to configuration exfiltration and unauthorized web shell drop in docroot.",
    events: [
      { id: 2001, time: "12:14:02", source: "nginx/access.log", facility: "nginx", severity: "INFO", raw: '203.0.113.188 - - [05/Sep/2026:12:14:02 +0530] "GET /robots.txt HTTP/1.1" 200 68', redactedRaw: '[EXT_IP_REDACTED] - - "GET /robots.txt HTTP/1.1" 200 68', hash: "c18f3a...1c6e14" },
      { id: 2002, time: "12:14:05", source: "nginx/access.log", facility: "nginx", severity: "WARN", raw: '203.0.113.188 - - [05/Sep/2026:12:14:05 +0530] "GET /.env HTTP/1.1" 200 482', redactedRaw: '[EXT_IP_REDACTED] - - "GET /.env HTTP/1.1" 200 482', hash: "d29a1b...2d7f15" },
      { id: 2003, time: "12:14:08", source: "nginx/access.log", facility: "nginx", severity: "WARN", raw: '203.0.113.188 - - [05/Sep/2026:12:14:08 +0530] "POST /api/upload.php HTTP/1.1" 200 128', redactedRaw: '[EXT_IP_REDACTED] - - "POST /api/upload.php HTTP/1.1" 200 128', hash: "e30b2c...3e8a16" },
      { id: 2004, time: "12:14:12", source: "journald", facility: "fim-agent", severity: "ALERT", raw: 'fim[410]: INTEGRITY VIOLATION: File created in webroot: /var/www/html/shell.php (SHA-256: 4f8a...9c1)', redactedRaw: 'fim[410]: INTEGRITY VIOLATION: File created in webroot: [PATH_REDACTED]', hash: "f41c3d...4f9b17" },
      { id: 2005, time: "12:14:15", source: "journald", facility: "systemd", severity: "CRITICAL", raw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", redactedRaw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", hash: "98e72a...9d8e7f" }
    ]
  },
  CAT5: {
    id: "PATH-3-CAT5",
    category: "Category V",
    categoryTitle: "Malicious Code / Ransomware Execution",
    statutoryRef: "CERT-In Dir. 2022 Para 5(i) - Cat V",
    ruleId: "SIGMA-CAT5-003",
    ruleName: "Rapid Mass File Renaming Burst & High Entropy Write Cascade",
    severity: "CRITICAL",
    conditions: "rate(file_rename) > 40/sec AND entropy(file_header) > 7.85 AND file_ext == '.locked'",
    mitreTechniques: ["T1486 - Data Encrypted for Impact", "T1489 - Service Stop"],
    confidenceScore: 0.99,
    attackerIp: "Internal Compromise (Lateral)",
    impactDescription: "Active ransomware payload encrypting critical customer database files and altering file extensions.",
    events: [
      { id: 3001, time: "12:20:10", source: "journald", facility: "kernel", severity: "INFO", raw: "kernel: [19842.102] process 5812 (crypt-locker) started by uid 1001", redactedRaw: "kernel: process [PID_REDACTED] started by uid 1001", hash: "11904a...5a1b2c" },
      { id: 3002, time: "12:20:12", source: "journald", facility: "fs-watcher", severity: "ALERT", raw: "fs-watcher[890]: High file write entropy (7.94 bits/byte) detected in /var/data/finance/", redactedRaw: "fs-watcher[890]: High file write entropy (7.94) detected in [PATH_REDACTED]", hash: "22015b...6b2c3d" },
      { id: 3003, time: "12:20:14", source: "journald", facility: "fs-watcher", severity: "CRITICAL", raw: "fs-watcher[890]: 48 files renamed to *.locked within 1000ms. Ransom note deposited: README_RECOVERY.txt", redactedRaw: "fs-watcher[890]: 48 files renamed to *.locked. Ransom note deposited", hash: "33126c...7c3d4e" },
      { id: 3004, time: "12:20:18", source: "journald", facility: "systemd", severity: "CRITICAL", raw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", redactedRaw: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL", hash: "98e72a...9d8e7f" }
    ]
  }
};

export const INITIAL_HASH_CHAIN = [
  {
    seq: 1,
    timestamp: "2026-09-05T12:00:10.104Z",
    source: "systemd-journal",
    eventSummary: "System boots into multi-user target; Go daemon spawned (PID 482)",
    rawSnippet: "systemd[1]: Started Barbarika Lightweight Log Tailing & Ingestion Daemon.",
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
    currHash: "7a52e6ff74e2d3b4f621a364be16a5ef4bb10ea99c687498c8bf102434de5412",
    verified: true,
  },
  {
    seq: 2,
    timestamp: "2026-09-05T12:01:22.408Z",
    source: "nginx/access.log",
    eventSummary: "Standard GET /api/v1/health from cloud heartbeat monitor [200 OK]",
    rawSnippet: '203.0.113.88 - - [05/Sep/2026:12:01:22 +0530] "GET /api/v1/health HTTP/1.1" 200 48',
    prevHash: "7a52e6ff74e2d3b4f621a364be16a5ef4bb10ea99c687498c8bf102434de5412",
    currHash: "c18f3a8b27521e8d9e262193cb9d46f5d023bf4101e4a5d89f81ca99551c6e14",
    verified: true,
  },
  {
    seq: 3,
    timestamp: "2026-09-05T12:04:15.890Z",
    source: "auth.log",
    eventSummary: "Scheduled cron job session opened for user msme_backup",
    rawSnippet: "CRON[1492]: pam_unix(cron:session): session opened for user msme_backup(uid=1001) by (uid=0)",
    prevHash: "c18f3a8b27521e8d9e262193cb9d46f5d023bf4101e4a5d89f81ca99551c6e14",
    currHash: "3f982b6b0c29f95de2c0451a94dc89163829ad4830ba293021f45610ecbb5119",
    verified: true,
  },
  {
    seq: 4,
    timestamp: "2026-09-05T12:08:44.212Z",
    source: "auth.log",
    eventSummary: "SSH connection received from external gateway 198.51.100.74 port 54210",
    rawSnippet: "sshd[2891]: Connection from 198.51.100.74 port 54210 on 192.168.10.45 port 22",
    prevHash: "3f982b6b0c29f95de2c0451a94dc89163829ad4830ba293021f45610ecbb5119",
    currHash: "b8971f45a8027ef5c98d6541f92e008d51ae10e82c5054901f409e51aa740c03",
    verified: true,
  },
  {
    seq: 5,
    timestamp: "2026-09-05T12:08:45.001Z",
    source: "auth.log",
    eventSummary: "Failed password for invalid user admin from 198.51.100.74 [Attempt 1/12]",
    rawSnippet: "sshd[2891]: Failed password for invalid user admin from 198.51.100.74 port 54210 ssh2",
    prevHash: "b8971f45a8027ef5c98d6541f92e008d51ae10e82c5054901f409e51aa740c03",
    currHash: "e4a9058b8f2c3d5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
    verified: true,
  },
  {
    seq: 6,
    timestamp: "2026-09-05T12:09:12.784Z",
    source: "auth.log",
    eventSummary: "Accepted password for msme_admin from 198.51.100.74 port 54228 ssh2",
    rawSnippet: "sshd[2940]: Accepted password for msme_admin from 198.51.100.74 port 54228 ssh2",
    prevHash: "e4a9058b8f2c3d5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
    currHash: "a123f45b67890cd12345ef678901ab234567cd8901ef234567890abcdef1234",
    verified: true,
  },
  {
    seq: 7,
    timestamp: "2026-09-05T12:09:18.115Z",
    source: "auth.log",
    eventSummary: "sudo: msme_admin : TTY=pts/0 ; PWD=/home/msme_admin ; USER=root ; COMMAND=/bin/bash",
    rawSnippet: "sudo[3010]: msme_admin : TTY=pts/0 ; PWD=/home/msme_admin ; USER=root ; COMMAND=/bin/bash",
    prevHash: "a123f45b67890cd12345ef678901ab234567cd8901ef234567890abcdef1234",
    currHash: "5f891b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f01",
    verified: true,
  },
  {
    seq: 8,
    timestamp: "2026-09-05T12:09:42.503Z",
    source: "systemd-journal",
    eventSummary: "SIGKILL received by daemon PID 482; host destruction initiated by adversary",
    rawSnippet: "systemd[1]: barbarika-daemon.service: Main process exited, code=killed, status=9/KILL",
    prevHash: "5f891b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f01",
    currHash: "98e72a1b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f",
    verified: true,
  }
];

export const getAnnexureIDataForScenario = (scenarioKey = "CAT3") => {
  const path = DETECTION_PATHS[scenarioKey] || DETECTION_PATHS.CAT3;
  return {
    formHeader: "CERT-IN INCIDENT REPORTING FORM (ANNEXURE I)",
    statutoryNotice: "Mandatory statutory filing under Sub-section (6) of Section 70B of The Information Technology Act, 2000 (Amended 2023). Ref: MeitY Direction No. 20(3)/2022-CERT-In dated 28th April 2022.",
    reportingDeadline: "6 Hours from Time of Incident Confirmation",
    reportedTo: "incident@cert-in.org.in",
    fields: {
      1: { label: "1. Name of the Organisation", value: "Barbarika FinTech Solutions Pvt. Ltd. (Udyam: UDYAM-MH-01-0089241)" },
      2: { label: "2. Contact Person Details", value: "Nandini Chitlangia, Designated CISO / IT Head (+91 98200 XXXXX / ciso@barbarika-fin.in)" },
      3: { label: "3. Incident Type / Statutory Classification", value: `${path.category}: ${path.categoryTitle}` },
      4: { label: "4. Time of Incident Detection", value: `05-Sep-2026 ${path.events[path.events.length - 2]?.time || '12:09:18'} IST (Triggered deterministically via Sigma Rule ${path.ruleId})` },
      5: { label: "5. Time of Initial Compromise / Intrusion", value: `05-Sep-2026 ${path.events[0]?.time || '12:08:44'} IST (Correlated across mTLS stream)` },
      6: { label: "6. Affected System(s) Details", value: "Hostname: prod-fin-vps01.msme-internal.net (Linux Ubuntu 24.04 LTS, IP: 203.0.113.19)" },
      7: { label: "7. Attack Origin / Attacker IP & IOCs", value: `Origin IP / Vector: ${path.attackerIp}. MITRE Techniques: ${path.mitreTechniques.join(", ")}` },
      8: { label: "8. Privilege Escalation / Execution Details", value: path.conditions },
      9: { label: "9. Host Status / Post-Intrusion Actions", value: "Attacker executed SIGKILL on host telemetry daemon. Sentry Inverted Watchdog triggered SUSPECTED_COMPROMISE (Adversarial Host Annihilation)" },
      10: { label: "10. Evidence Provenance & Cryptographic Integrity", value: "Pre-compromise logs preserved in Isolated Black-Box Sentry Vault. Append-only SHA-256 chain: 47 records cryptographically intact (0 tampering detected)" },
      11: { label: "11. Impact on Critical Operations / Customer Data", value: "Customer PII filtered at edge via Presidio NER. Zero customer database exfiltration recorded prior to host isolation" },
      12: { label: "12. Immediate Remediation & Containment Measures", value: "1. Firewall rule dropped all traffic from attacker source\n2. Primary server isolated from internal subnet\n3. Sentry Vault locked in read-only forensic mode\n4. CERT-In statutory notice generated within 18 minutes of intrusion" }
    }
  };
};
