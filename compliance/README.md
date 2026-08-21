# compliance — reporting + demo

Owner: Krishna Solanki (Compliance & Demo).

## Scope

- **PDF generation:** ReportLab, auto-filling the official CERT-In Incident Reporting Format
  (Annexure I) from a confirmed incident's data — attack vectors, source IPs (unmasked only after
  authenticated reviewer action), affected assets, discovery timeline, containment steps taken.
- **Email dispatch builder:** composes a formatted submission draft addressed to
  `incident@cert-in.org.in`. **Never wires up actual sending.** The flow always ends at a human
  clicking send in their own mail client, or an explicit, clearly-labeled "this is a demo, not a
  real submission" state on stage.
- **Demo attack scripts:** brute-force / exploit-pattern / mass-file-modification replay scripts
  used to trigger the 3 live detection paths in `../rules/` during the demo. **Target only a
  disposable local VM/container set up for this purpose — never a real host, never this
  development machine.**
- **Stage demo script:** the 3-minute choreography from the architecture blueprint
  (`../../architecture/barbarika_technical_blueprint.md` §5) — hook, architecture, attack
  injection, controlled host disruption, evidence provenance walkthrough, human review, export.
  Keep a rehearsed, pre-recorded fallback capture of a full successful run, in case the live
  network/demo hardware fails on stage.

## Explicitly out of scope here

- No detection logic (that's `../rules/`), no vault/storage logic (that's `../sentry/`).
