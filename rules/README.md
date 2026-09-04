# rules — detection schema + YAML rules

Owner: Anishka Garg (Detection Rules).

## Scope

- Normalized Pydantic event schema shared with `../sentry/` and the agent.
- Versioned YAML detection rules, Sigma-style. **Four CERT-In Annexure I
  categories are live-detected** (iii, iv, v, x); the other 16 identifiers exist
  in `CertInCategory` for schema completeness only — never describe them as
  "supported".
- Every rule ships with a test that proves it fires on an attack fixture **and**
  does not fire on an adjacent benign fixture (false-positive control matters as
  much as true-positive).

## Reporting language

Any doc, UI copy, or pitch text this component's output feeds must say
**"20/20 categories represented, 4/20 live-detected"** — never "20 categories
supported".

## Detection types (`schema_version: 1`)

The first slice defined one shape: a two-step, single-`source` `sequence`. That
is unchanged. Three more types were added under the same schema version, plus
`sequence` was generalised to N steps. `evaluate_rule(rule, events) ->
list[RuleMatch]` stays the single entry point and dispatches on `detection.type`.

| type          | what it matches | used by |
|---------------|-----------------|---------|
| `sequence`    | ordered phases from **one source** inside a window anchored at the last step; **2 or more** steps | iii (both rules) |
| `single`      | one event matching a predicate | x |
| `threshold`   | ≥ `min_count` events matching one predicate from one source in `within_seconds` | *(available; no category rule yet)* |
| `correlation` | every `arm` satisfied inside one `within_seconds` window, **any order, across different sources** | iv, v |

`EventPredicate` now takes `raw_message_regex` and/or `source_regex` (both
optional, AND-combined). `source_regex` is what lets a `correlation` arm select
one telemetry stream (`…/nginx`) from another (`…/fim`). Regexes are validated
for compilability at load time.

Public API (imported by `../sentry/`) is unchanged and additive:
`from barbarika_rules import NormalizedEvent, DetectionRule, RuleMatch, evaluate_rule, load_rule`.

## The rules (`rules/v1/`)

| file | category | type | fires when |
|------|----------|------|------------|
| `category_iii_ssh_bruteforce.yaml` | iii | sequence (2) | ≥10 failed SSH auths from one source in 60s, then a success. **First slice, `experimental`** — a brute-force *precursor* signal. Pinned by `../sentry/tests/test_detect.py`; left as-is. |
| `category_iii_ssh_privilege_escalation.yaml` | iii | sequence (3) | the above **plus** a privileged `sudo` shell (`su` / `bash` / `sh`) from that source within 120s. **`stable` — the rule to cite for a confirmed intrusion.** |
| `category_iv_web_defacement.yaml` | iv | correlation | an nginx exploit-pattern request **and** a create/write/rename/delete under `/var/www` (agent FIM) within 120s. Log pattern alone is not sufficient evidence per the audit — the file-integrity arm is required. |
| `category_v_ransomware_burst.yaml` | v | correlation | ≥10 file create/write/rename events under monitored data dirs **and** a canary-file alteration within 30s. The canary arm is the FP control (a backup burst never touches the canary). |
| `category_x_appserver_attack.yaml` | x | single | one nginx line carrying an unambiguous app-layer attack (UNION SELECT, boolean tautology, `/etc/passwd`, `../../`, `/.git/`, `/.env`, command injection, or a scanner UA). |

### The two Category (iii) rules

`category_iii_ssh_bruteforce.yaml` and `category_iii_ssh_privilege_escalation.yaml`
are both category `iii`, so `../sentry/`'s detector (which buckets by category)
evaluates both and can raise **two** incidents for one intrusion — a brute-force
precursor and the confirmed privilege escalation. For a single-incident demo,
the integration team can filter the loaded rule set to `status == "stable"`
(a one-line change in `../sentry/app/detect.py::load_rules`, their side). The
first-slice rule is intentionally not deleted: `../sentry/tests/test_detect.py`
depends on its two-step behaviour and `sentry/` is out of scope for this package.

## Telemetry the new rules need

`category_iv` and `category_v` consume **file-integrity events the currently
connected agent does not emit yet**. The exact `source` / `raw_message` /
`category` shapes every rule expects are specified in
[`TELEMETRY_CONTRACT.md`](./TELEMETRY_CONTRACT.md) — hand that to the integration
team (agent `candidateCategory` + a FIM emitter).

## Running the tests

```sh
uv run pytest          # from rules/
```

Fixtures are YAML lists of `NormalizedEvent` dicts in `tests/fixtures/`. Per
rule: one `*_attack.yaml` that produces exactly one match and one `*_benign.yaml`
that produces zero. `tests/test_engine.py` pins the evaluator behaviour per
detection type, including that two-step `sequence` output is unchanged.
