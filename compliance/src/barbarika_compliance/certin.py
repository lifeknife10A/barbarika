"""Authentic CERT-In taxonomy + statutory text + compliance enrichment.

- INCIDENT_TYPES: the 20 incident-type labels VERBATIM from the official
  Incident Reporting Form (certinirform.pdf) — used as the form's checklist.
- CATEGORY_ID_TO_TYPE: maps our CERT-In Annexure I ids (i..xx, the ids used by
  the detection rules / vault) to the form's checklist label, so the matched
  incident type is ticked on the form.
- ENRICHMENT: compliance-owned mapping from category id → MITRE ATT&CK techniques
  and an attack-vector sentence (the vault/rules do not carry MITRE fields).
- STATUTORY_NOTICE / REPORTING_CHANNEL: verbatim from the 28-Apr-2022 Directions.
"""

from __future__ import annotations

# The 20 incident-type labels exactly as printed on certinirform.pdf, in order.
INCIDENT_TYPES: list[tuple[str, str]] = [
    ("i", "Targeted scanning/probing of critical networks/systems"),
    ("ii", "Compromise of critical systems/information"),
    ("iii", "Unauthorised access of IT systems/data"),
    ("iv", "Defacement or intrusion into the website"),
    ("v", "Malicious code attacks"),
    ("vi", "Attack on servers such as Database, Mail and DNS and network devices such as Routers"),
    ("vii", "Identity Theft, spoofing and phishing attacks"),
    ("viii", "DoS/DDoS attacks"),
    ("ix", "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks"),
    ("x", "Attacks on Application such as E-Governance, E-Commerce etc."),
    ("xi", "Data Breach"),
    ("xii", "Data Leak"),
    ("xiii", "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers"),
    ("xiv", "Attacks or incident affecting Digital Payment systems"),
    ("xv", "Attacks through Malicious mobile Apps"),
    ("xvi", "Fake mobile Apps"),
    ("xvii", "Unauthorised access to social media accounts"),
    ("xviii", "Attacks or malicious/ suspicious activities affecting Cloud computing systems/servers/software/applications"),
    ("xix", "Attacks or malicious/suspicious activities affecting systems/ servers/ networks/ software/ applications related to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, additive manufacturing, Drones"),
    ("xx", "Attacks or malicious/ suspicious activities affecting systems/ servers/software/ applications related to Artificial Intelligence and Machine Learning"),
]

CATEGORY_ID_TO_TYPE: dict[str, str] = {cid: label for cid, label in INCIDENT_TYPES}


def category_numeral(cid: str) -> str:
    """'iii' -> 'Category (iii)'."""
    return f"Category ({cid})"


def category_label(cid: str | None) -> str:
    """Official incident-type label for a category id, or a safe fallback."""
    if cid and cid in CATEGORY_ID_TO_TYPE:
        return CATEGORY_ID_TO_TYPE[cid]
    return "Other (Please Specify)"


# Compliance-owned enrichment (MITRE ATT&CK + attack-vector prose). The detection
# rules carry only free-text descriptions, so the CISO's compliance layer supplies
# the standard technique mapping for the report's IOC / attack-vector fields.
ENRICHMENT: dict[str, dict[str, object]] = {
    "iii": {
        "mitre": ["T1110.001 Brute Force: Password Guessing",
                  "T1078 Valid Accounts",
                  "T1548.003 Abuse Elevation Control: Sudo and Sudo Caching"],
        "attack_vector": "External SSH credential brute-force followed by successful "
                         "authentication and privileged sudo elevation on the host.",
    },
    "iv": {
        "mitre": ["T1190 Exploit Public-Facing Application",
                  "T1505.003 Server Software Component: Web Shell",
                  "T1565.001 Data Manipulation: Stored Data Manipulation"],
        "attack_vector": "Web-application exploit request correlated with an unauthorised "
                         "file-integrity change under the web root (defacement/intrusion).",
    },
    "v": {
        "mitre": ["T1486 Data Encrypted for Impact",
                  "T1490 Inhibit System Recovery",
                  "T1083 File and Directory Discovery"],
        "attack_vector": "Rapid multi-file modification burst across data directories with "
                         "canary-file alteration, consistent with ransomware/malicious code.",
    },
    "x": {
        "mitre": ["T1190 Exploit Public-Facing Application",
                  "T1059 Command and Scripting Interpreter",
                  "T1213 Data from Information Repositories"],
        "attack_vector": "Application-layer exploitation (SQL injection / traversal / "
                         "scanner activity) against the web/application tier.",
    },
    "ii": {
        "mitre": ["T1485 Data Destruction", "T1499 Endpoint Denial of Service"],
        "attack_vector": "Telemetry loss on a monitored host correlated with recent "
                         "high-confidence intrusion evidence (dead-man-switch candidate).",
    },
}


def enrichment(cid: str | None) -> dict[str, object]:
    return ENRICHMENT.get(cid or "", {"mitre": [], "attack_vector": "Not classified."})


# Verbatim statutory basis (Directions No. 20(3)/2022-CERT-In dated 28 April 2022).
STATUTORY_NOTICE = (
    "Mandatory reporting under sub-section (6) of section 70B of the Information "
    "Technology Act, 2000, read with Rule 12(1)(a) of the CERT-In Rules, 2013, "
    "pursuant to CERT-In Directions No. 20(3)/2022-CERT-In dated 28 April 2022. "
    "Cyber incidents mentioned in Annexure I must be reported to CERT-In within "
    "6 hours of noticing. Failure to report may invite action under sub-section (7) "
    "of section 70B."
)

REPORTING_CHANNEL = {
    "email": "incident@cert-in.org.in",
    "phone": "1800-11-4949",
    "fax": "1800-11-6969",
    "address": "CERT-In, Electronics Niketan, CGO Complex, New Delhi 110003",
}
