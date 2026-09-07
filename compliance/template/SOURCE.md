# Official CERT-In source material (provenance)

The Annexure I incident report is built by filling the **authentic official
CERT-In Incident Reporting Form** — not a homemade layout. The source artifacts
below were fetched from CERT-In and are stored here for provenance and offline use.

| File | Official source URL | Retrieved |
|------|---------------------|-----------|
| `CERT-In_Incident_Reporting_Form.pdf` | https://www.cert-in.org.in/PDF/certinirform.pdf | 2026-09-05 |
| `CERT-In_Directions_70B_28.04.2022.pdf` | https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf | 2026-09-05 |

## What these define

- **Directions dated 28 April 2022** (`No. 20(3)/2022-CERT-In`): mandate that cyber
  incidents "as mentioned in Annexure I" be reported to CERT-In **within 6 hours** of
  noticing (Direction (ii)); logs kept 180 days (Direction (iv)); reporting channel
  `incident@cert-in.org.in` / Phone 1800-11-4949 / Fax 1800-11-6969. **Annexure I of the
  Directions is the list of the 20 incident TYPES (i–xx)** to be reported — NOT a
  fillable form. Statutory penalty for non-compliance: sub-section (7) of section 70B.
- **Incident Reporting Form** — the submittable PDF's page 1 is the **authentic INTERACTIVE
  form** `cert_in_annexure_i_interactive.pdf` (an AcroForm with 44 named fields; its recorded
  SHA-256 in `cert_in_annexure_i_interactive.sha256` is verified before every run). We fill
  the form's real fields *by name* and flatten to a static page — so text sits inside the
  cells (no divider ever cuts a value), the output is pixel-identical to the government form,
  it stays on one page, and it needs **no LibreOffice** (pure `pypdf`). Pipeline:
  1. **`acroform.py`** maps our re-verified incident context onto the 44 field names
     (`build_field_values`), writes our own correctly-encoded Helvetica appearance streams
     with **shrink-to-fit** so long single-line values are never clipped, draws a thin tick
     for the matched checkboxes, and flattens the page (`fill_form_pdf`).
  2. **`report.build_pdf`** appends the reportlab Detailed Incident Report annexure after the
     flattened form page and locks the metadata.
  The **editable** companion (`/report.docx`, "Editable .docx" button) is the same form
  filled into a Word template's real cells with `python-docx` (`formdoc.py`, no LibreOffice);
  `build_template.py` one-time-repairs that DOCX template (renderable checkbox glyph +
  clean single-column Incident Type). The authentic flat `certinirform.pdf` is kept for
  provenance. The interactive template + the flat PDF share the same field set:
  - "I am: [ ] the effected entity  [ ] reporting incident affecting other entity"
  - **Contact Information of the Reporter**: Name & Role/Title (Individual/Organization);
    Organization name (if any); Contact No.; Email; Address.
  - **Basic Incident Details**: Affected entity (if not the reporter); **Incident Type**
    (the 20-type checklist, exact form labels); "Is the affected system/network critical
    to the organization's mission? (Yes/No)"; **Basic Information of Affected System**
    (Domain/URL, IP Address, Operating System, Make/Model/Cloud details, Affected
    Application details, Location incl. City/Region/Country, Network and name of ISP);
    **Brief description of Incident** with Occurrence date & time and Detection date & time
    (dd/mm/yyyy hh:mm).
  - Note (i)(ii)(iii) + Mail/Fax footer.

The form's own Note (ii): "It is not mandatory to fill and/or sign this form. Incidents
may also be reported by providing relevant information …", and Note (iii) permits the
reporting entity to "also provide relevant information other than mentioned in this form".
On that basis (and the Directions' requirement that logs accompany the report), Barbarika
auto-fills the form for the reporter and appends a **Detailed Incident Report** annexure
modelled on NIST SP 800-61 / SANS: executive summary, incident timeline, technical
analysis & detection rationale, impact & scope, indicators of compromise, cryptographic
integrity attestation, the unmasked chronological evidence log, and response & remediation.
