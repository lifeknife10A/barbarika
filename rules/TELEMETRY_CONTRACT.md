# Telemetry contract for the detection rules (`rules/` → integration team)

What the four live rules need Sentry to hand `evaluate_rule` as
`NormalizedEvent`s. Sentry builds a `NormalizedEvent` from a stored event as:
`source` ← agent `source`, `raw_message` ← the exact log line
(`payload.raw_content`), `category` ← the agent's `candidateCategory` tag. The
rules match on `source` (regex) and `raw_message` (regex) only — **not** on
`event_type`, so `event_type` values below are informative.

Owner split: the **agent team** adds the `candidateCategory` cases and the FIM
emitter; the **Sentry team** optionally adds the one-line `status` filter in
§5. `rules/` needs no further change once telemetry matches this.

---

## 1. Category (iii) — already satisfied, no agent change

`category_iii_ssh_privilege_escalation.yaml` needs failed SSH, successful SSH,
and a privileged `sudo` line, all from one `source`, all tagged `iii`.

| stream | `source` (example) | `raw_message` (verbatim log line) | `category` |
|--------|--------------------|-----------------------------------|------------|
| auth   | `primary-srv-01/auth` | `sshd[9901]: Failed password for root from 185.220.101.4 port 41001 ssh2` | `iii` |
| auth   | `primary-srv-01/auth` | `sshd[9907]: Accepted password for ubuntu from 185.220.101.4 port 4107 ssh2` | `iii` |
| auth   | `primary-srv-01/auth` | `sudo:   ubuntu : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash` | `iii` |

`mapping.go :: candidateCategory` already maps `ssh_failed_login` / `ssh_login` /
`sudo_exec` → `iii`. The privileged-shell test is on `raw_message`
(`COMMAND=…/su|bash|sh|zsh`), so a `sudo apt update` line is correctly ignored.
**Nothing to do.**

---

## 2. Category (x) — nginx data exists, needs one `candidateCategory` case

`category_x_appserver_attack.yaml` is a `single` rule.

| field | value |
|-------|-------|
| `source` | `<agent_id>/nginx` (regex the rule applies: `/nginx(?:\b|$)`) |
| `raw_message` | the raw nginx access-log line, unmodified |
| `category` | **`x`** — add this |

Add to `mapping.go :: candidateCategory` (or a small classifier next to
`classifyEventType`): when `event_type == "http_request"` **and** the request
line matches an app-layer-exploit signature, tag `x`. Signatures (same set the
rule regex uses): `UNION SELECT` (raw / `+` / `%20`-encoded), boolean tautology
(`' or 1=1`, `' or '1'='1`), `/etc/passwd`, `../../` (or `%2e%2e%2f`), `/.git/`,
`/.svn/`, `/.env`, `information_schema`, `xp_cmdshell`, command injection
(`;id`, `|whoami`, `$(…)`), or a scanner UA (`sqlmap`, `nikto`, `nuclei`,
`wpscan`, `masscan`, `acunetix`).

---

## 3. Category (iv) — needs the FIM emitter **and** an nginx `candidateCategory` case

`category_iv_web_defacement.yaml` is a `correlation` rule with two arms; both
arms' events must be tagged `iv` and land within 120 s.

### Arm A — web exploit request (nginx, exists today)

| field | value |
|-------|-------|
| `source` | `<agent_id>/nginx` |
| `raw_message` | raw nginx line |
| `category` | **`iv`** |

Tag `iv` when `event_type == "http_request"` and the line matches a
*defacement-oriented* signature: `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`,
`/administrator/`, `/wp-config.php`, `/.env`, `/.git/`, a webshell name
(`shell.php`, `c99.php`, `wso.php`, `cmd.php`, `up*.php`), a `.php` / `.phtml`
under `/upload(s)/`, or `../../` traversal.
**Precedence:** if a request matches both the §2 (x) set and this set, tag `x`
(app-layer exploitation is the stronger claim). A request that matches neither
gets no category.

### Arm B — web-root file change (NEW: FIM emitter)

| field | value |
|-------|-------|
| `source` | `<agent_id>/fim` (regex the rule applies: `/fim(?:\b|$)`) |
| `event_type` | `file_change` |
| `raw_message` | `FIM <OP> <abs_path> sha256=<hex\|->` |
| `category` | **`iv`** when `<abs_path>` is under the configured web root (default `/var/www`) |

`<OP>` ∈ `CREATE` `WRITE` `RENAME` `REMOVE` `CHMOD` (rule arm matches
`CREATE|WRITE|RENAME|REMOVE`). `sha256=` is the new content hash, or `-` when the
file was removed / unreadable. One space between each token.
Example: `FIM WRITE /var/www/html/index.php sha256=4c2a9f1e…7d6c`

The original `agent/internal/watcher/watcher.go` (fsnotify) already produces the
needed operations and a per-file SHA-256; it just needs a formatter to this
`raw_message` string, a `source` of `<agent_id>/fim`, and wiring into the
connected `agent/barbarika-agent` egress path.

---

## 4. Category (v) — FIM emitter (burst + canary)

`category_v_ransomware_burst.yaml` is a `correlation` rule; both arms tagged `v`,
within 30 s.

### Arm A — file modification burst

| field | value |
|-------|-------|
| `source` | `<agent_id>/fim` |
| `event_type` | `file_change` |
| `raw_message` | `FIM <OP> <abs_path> sha256=<hex\|->` (same format as §3B) |
| `category` | **`v`** when `<abs_path>` is under a monitored data dir and **not** under the web root |
| threshold | rule needs ≥ 10 such events in the window |

### Arm B — canary alteration

| field | value |
|-------|-------|
| `source` | `<agent_id>/fim` |
| `event_type` | `canary_tampered` |
| `raw_message` | `FIM CANARY <OP> <abs_path> sha256=<hex\|->` |
| `category` | **`v`** (always) |

Example: `FIM CANARY WRITE /srv/data/.canary_token.docx sha256=00ba…`
The literal token `CANARY` as the second word is what separates arm B from arm A
(arm A's regex explicitly excludes lines containing `CANARY`). The agent already
has `isCanaryPath()` / `canary_tampered` in `watcher.go` / `normalizer.go`.

---

## 5. Sentry: optional one-line `status` filter

`../sentry/app/detect.py :: load_rules` currently loads every `*.yaml`. Both
Category (iii) rules then fire, so one intrusion can raise two incidents
(brute-force precursor + confirmed privilege escalation). For a single-incident
demo, load only stable rules:

```python
rules.append(load_rule(path))            # becomes:
rule = load_rule(path)
if rule.status == "stable":
    rules.append(rule)
```

`category_iii_ssh_bruteforce.yaml` is the only `experimental` rule; it is kept
because `../sentry/tests/test_detect.py` pins its two-step behaviour. If that
test is updated to the completed rule, the first-slice file can simply be
deleted instead.

---

## 6. Summary of asks

| # | Team | Change |
|---|------|--------|
| 1 | agent | `candidateCategory`: `http_request` + app-layer-exploit signature → `x` |
| 2 | agent | `candidateCategory`: `http_request` + defacement signature → `iv` (x wins ties) |
| 3 | agent | FIM emitter: `source=<agent_id>/fim`, `event_type` `file_change` / `canary_tampered`, `raw_message` `FIM [CANARY] <OP> <path> sha256=<hex\|->` |
| 4 | agent | FIM `candidateCategory`: path under web root → `iv`; other monitored data dir → `v`; `canary_tampered` → `v` |
| 5 | sentry | *(optional)* load only `status == "stable"` rules |

Fixtures in `tests/fixtures/` use `primary-srv-01/...` sources and the exact
`raw_message` strings above — they are the reference for what "matching
telemetry" looks like.
