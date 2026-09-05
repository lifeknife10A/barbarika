"""Barbarika compliance — fill the official CERT-In Incident Reporting Form.

Reads a confirmed incident from the Sentry evidence vault (read-only),
independently re-verifies the hash chain, unseals the correlated evidence, and
renders the authentic CERT-In Incident Reporting Form (certinirform.pdf layout)
plus Barbarika evidence-integrity annexes, as a flat non-editable PDF.
"""

__version__ = "0.1.0"
