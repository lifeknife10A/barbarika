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
- **Incident Reporting Form**: shipped here twice — the authentic
  `CERT-In_Incident_Reporting_Form.pdf` (=`certinirform.pdf`) and a DOCX conversion of the
  same form (`CERT-In_Incident_Reporting_Form.docx`). Both are filled, giving two outputs:
  - **Submittable PDF** (`formfill.py`, page 1): writes our values **directly onto the
    authentic PDF**, located by the form's OWN text — for each field it finds the printed
    label, reads its baseline, and places the value on that exact baseline at the label's
    font size (checkboxes get an `X`). Anchored to the form's own layout, so there are no
    brittle hardcoded coordinates and values sit on the form's lines. Uses `pymupdf`.
  - **Editable DOCX** (`formdoc.py`): fills the values into the form's real Word table
    cells with `python-docx`, so the reporter gets an editable copy (alignment is inherent
    to the cells). A `docx_to_pdf()` helper can render it via headless LibreOffice **where
    `soffice` is available** — but the primary submittable PDF above needs no LibreOffice.
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
