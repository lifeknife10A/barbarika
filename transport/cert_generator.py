"""Pure-Python generator for the demo-only mTLS PKI.

This is a drop-in alternative to ``scripts/generate_demo_certs.sh`` for
contributors who do not have ``openssl``/``bash`` handy (e.g. on Windows). It
produces certificates that match the OpenSSL profiles in ``certs/*.cnf`` field
for field, so either tool yields an interchangeable trust chain:

* **CA** — ``CN=Barbarika Demo-Only Local CA`` (see ``certs/ca.cnf``), RSA-3072,
  ``basicConstraints critical CA:true, pathlen:0``, ``keyUsage keyCertSign,cRLSign``.
* **Server** — ``CN=sentry.local`` (see ``certs/server.cnf``), RSA-2048,
  ``extendedKeyUsage serverAuth``, SAN ``DNS:sentry.local, DNS:localhost, IP:127.0.0.1``.
* **Client** — ``CN=primary-srv-01`` (see ``certs/client.cnf``), RSA-2048,
  ``extendedKeyUsage clientAuth``, SAN ``URI:urn:barbarika:demo:agent:primary-srv-01``.

These identities are **demo-only, not production PKI**. They are short-lived
(30 days) and must never be installed in a system/browser trust store. Private
keys are written owner-only (0600) and are git-ignored.

Usage:
    python cert_generator.py            # refuses to overwrite an existing set
    python cert_generator.py --force    # rotate/overwrite the local demo identities
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Matches scripts/generate_demo_certs.sh: short-lived demo identities.
VALIDITY_DAYS = 30
CA_KEY_BITS = 3072
LEAF_KEY_BITS = 2048
_ORG = "Barbarika DEMO ONLY"

# The six artifacts, in the same names the shell script and sentry/ expect.
_ARTIFACT_NAMES = (
    "demo-ca.key",
    "demo-ca.crt",
    "demo-server.key",
    "demo-server.crt",
    "demo-client.key",
    "demo-client.crt",
)


class DemoCertificatesExistError(RuntimeError):
    """Raised when demo certificates already exist and ``force`` was not set."""


def _rsa_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _write(path: Path, data: bytes, mode: int) -> None:
    path.write_bytes(data)
    os.chmod(path, mode)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    _write(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=0o600,
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    _write(path, cert.public_bytes(serialization.Encoding.PEM), mode=0o644)


def generate_mtls_pki(output_dir: str = "./certs", *, force: bool = False) -> dict[str, str]:
    """Generate the demo CA + server + client identities into ``output_dir``.

    Returns a mapping of artifact -> path. Refuses to overwrite an existing set
    unless ``force`` is True (mirrors ``generate_demo_certs.sh``), because
    regenerating the CA silently invalidates every previously issued identity.
    """

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    existing = [name for name in _ARTIFACT_NAMES if (out / name).exists()]
    if existing and not force:
        raise DemoCertificatesExistError(
            "Refusing to overwrite existing demo certificates "
            f"({', '.join(existing)}). Pass force=True (CLI: --force) to rotate them."
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(days=1)  # tolerate small clock skew
    not_after = now + datetime.timedelta(days=VALIDITY_DAYS)

    # --- CA (self-signed root) -- certs/ca.cnf --------------------------------
    ca_key = _rsa_key(CA_KEY_BITS)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Barbarika Demo-Only Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Not Production PKI"),
        ]
    )
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    def _issue_leaf(
        *,
        common_name: str,
        org_unit: str,
        san: x509.SubjectAlternativeName,
        extended_key_usage: x509.ExtendedKeyUsage,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        leaf_key = _rsa_key(LEAF_KEY_BITS)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORG),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(extended_key_usage, critical=False)
            .add_extension(san, critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return leaf_key, cert

    # --- Server -- certs/server.cnf -------------------------------------------
    server_key, server_cert = _issue_leaf(
        common_name="sentry.local",
        org_unit="Demo Sentry Server",
        san=x509.SubjectAlternativeName(
            [
                x509.DNSName("sentry.local"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]
        ),
        extended_key_usage=x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
    )

    # --- Client -- certs/client.cnf -------------------------------------------
    client_key, client_cert = _issue_leaf(
        common_name="primary-srv-01",
        org_unit="Demo Primary Agent",
        san=x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier("urn:barbarika:demo:agent:primary-srv-01")]
        ),
        extended_key_usage=x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
    )

    _write_key(out / "demo-ca.key", ca_key)
    _write_cert(out / "demo-ca.crt", ca_cert)
    _write_key(out / "demo-server.key", server_key)
    _write_cert(out / "demo-server.crt", server_cert)
    _write_key(out / "demo-client.key", client_key)
    _write_cert(out / "demo-client.crt", client_cert)

    return {
        "ca_key": str(out / "demo-ca.key"),
        "ca_cert": str(out / "demo-ca.crt"),
        "server_key": str(out / "demo-server.key"),
        "server_cert": str(out / "demo-server.crt"),
        "client_key": str(out / "demo-client.key"),
        "client_cert": str(out / "demo-client.crt"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the DEMO-ONLY mTLS PKI (CA + server + client)."
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent / "certs"),
        help="Directory to write the demo identities into (default: transport/certs).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing demo set (rotates the CA and all leaves).",
    )
    args = parser.parse_args(argv)

    try:
        generate_mtls_pki(args.output_dir, force=args.force)
    except DemoCertificatesExistError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[✓] DEMO-ONLY PKI created in {args.output_dir} (valid {VALIDITY_DAYS} days).")
    print("    Do not use as production PKI or install the CA system-wide.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
