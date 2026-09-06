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
- **Incident Reporting Form**: the page-1 source is the DOCX of the official form
  (`CERT-In_Incident_Reporting_Form.docx`); the authentic PDF (`certinirform.pdf`) is kept
  for provenance. The form is filled through the **document model**, not by drawing on a
  flat PDF — because coordinate-drawn text has no notion of the form's table cell walls and
  the form's vertical dividers slice through typed values. The pipeline:
  1. **`build_template.py`** (one-time) repairs the raw DOCX conversion into a clean,
     render-faithful template: it swaps the Wingdings checkbox glyph (U+F06F, tofu without
     Wingdings) for U+2610 BALLOT BOX in DejaVu Sans, and rebuilds the "Incident Type" block
     — which the conversion had flattened into one cell of scrambled run-on text — into a
     clean single-column checklist of the 20 verbatim labels from `certin.INCIDENT_TYPES`.
  2. **`formdoc.py`** fills our values into the form's real Word table cells with
     `python-docx` (text wraps inside each cell — no divider ever cuts a value), then
     converts the filled DOCX to PDF with headless LibreOffice (`docx_to_pdf`).
  3. **`formticks.py`** stamps the checkbox **X** marks onto the rendered PDF with `pymupdf`,
     each box located by searching the PDF for its label (I-am / Individual-Organization /
     the matched Incident Type category). A small X in a box is position-tolerant.
  The same filled DOCX is also served as an **editable** deliverable (`/report.docx`).
  Requires system LibreOffice **with the Writer module** (`libreoffice-writer`).
  The form's fields are:
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
