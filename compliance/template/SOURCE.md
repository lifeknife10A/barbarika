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
- **Incident Reporting Form** (`certinirform.pdf`): the actual single-page CERT-In form
  the entity fills. This exact PDF is shipped here and used as page 1 of the output:
  `formfill.py` **stamps our values directly onto this authentic PDF** at the form's own
  measured coordinates (checkboxes get an `X`, blanks get text) — it is not redrawn. Its
  fields are:
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
