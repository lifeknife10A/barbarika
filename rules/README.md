# rules — detection schema + YAML rules

Owner: Anishka Garg (Detection Rules).

## Scope

- Normalized Pydantic event schema shared with `../sentry/`.
- Versioned YAML detection rules, Sigma-style. **Exactly 3 need to be real, tested, and reliably
  demoable:**
  1. **Category (iii) — Unauthorised access:** ≥10 failed SSH attempts within 60s, followed by a
     successful auth from an unrecognized source, followed by a privileged `sudo` execution.
  2. **Category (iv) — Defacement/unauthorised changes:** Nginx exploit-pattern requests
     (`/.env`, SQLi payloads) correlated with unauthorized file modifications under `/var/www`
     via the `fsnotify` signal from `../agent/` — log pattern-matching alone is not sufficient
     evidence per the audit; the file-integrity signal is required.
  3. **Category (v) — Malicious code / ransomware-like:** rapid multi-file modification plus
     canary-file alteration across monitored data directories.
- The remaining 17 statutory categories from Annexure I exist as **schema entries only** — do not
  write detection logic for them, and never describe them as "supported."
- Test suite proving each of the 3 rules fires on the intended fixture and does *not* fire on
  adjacent benign fixtures (false-positive check matters as much as true-positive).

## Reporting language

Any doc, UI copy, or pitch text this component's output feeds must say "20/20 categories
represented, 3/20 live-detected" — never "20 categories supported."

## Current first slice

- `NormalizedEvent` provides the six-field Pydantic V2 contract: `event_id`, `occurred_at`,
  `detected_at`, `source`, `raw_message`, and `category`.
- `CertInCategory` represents all 20 Annexure I identifiers. Representation is not a claim of
  live detection coverage.
- `rules/v1/category_iii_ssh_bruteforce.yaml` detects 10 or more failed SSH authentications from
  one normalized source within 60 seconds followed by a successful authentication. The later
  unrecognized-source and privileged-`sudo` correlations described above are not asserted by this
  first-slice rule.

Run the tests independently with:

```sh
uv run pytest
```
