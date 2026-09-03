"""Real assertions for the demo PKI: chain validity, EKU, SAN, key usage.

These go beyond "a file exists / contains BEGIN CERTIFICATE": each leaf is
cryptographically verified against the CA, and the fields that make the
documented mTLS command work (server SAN, client/server EKU) are checked
directly. That is what catches a wrong CN/SAN before it reaches a handshake.
"""

from __future__ import annotations

import ipaddress
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cert_generator import VALIDITY_DAYS, DemoCertificatesExistError, generate_mtls_pki


def _load(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def _cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _assert_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Raises cryptography.exceptions.InvalidSignature if the link is broken."""
    issuer.public_key().verify(
        child.signature,
        child.tbs_certificate_bytes,
        padding.PKCS1v15(),
        child.signature_hash_algorithm,
    )


class DemoPkiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.paths = generate_mtls_pki(self._tmp.name)
        self.ca = _load(self.paths["ca_cert"])
        self.server = _load(self.paths["server_cert"])
        self.client = _load(self.paths["client_cert"])

    def test_all_artifacts_created(self) -> None:
        for path in self.paths.values():
            self.assertTrue(Path(path).exists(), path)

    def test_private_keys_are_owner_only(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX file modes only")
        for key in ("ca_key", "server_key", "client_key"):
            mode = oct(Path(self.paths[key]).stat().st_mode)[-3:]
            self.assertEqual(mode, "600", key)

    def test_ca_is_self_signed_root(self) -> None:
        self.assertEqual(_cn(self.ca), "Barbarika Demo-Only Local CA")
        self.assertEqual(self.ca.subject, self.ca.issuer)
        _assert_signed_by(self.ca, self.ca)  # self-signed

        bc = self.ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca)
        self.assertEqual(bc.path_length, 0)

        ku = self.ca.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign and ku.crl_sign)
        self.assertFalse(ku.digital_signature)

    def test_server_cert_chains_to_ca_with_serverauth_and_sans(self) -> None:
        self.assertEqual(_cn(self.server), "sentry.local")
        _assert_signed_by(self.server, self.ca)

        eku = self.server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)

        san = self.server.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["sentry.local", "localhost"])
        self.assertEqual(
            san.get_values_for_type(x509.IPAddress),
            [ipaddress.IPv4Address("127.0.0.1")],
        )

        bc = self.server.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(bc.ca)

    def test_client_cert_chains_to_ca_with_clientauth_and_uri_san(self) -> None:
        self.assertEqual(_cn(self.client), "primary-srv-01")
        _assert_signed_by(self.client, self.ca)

        eku = self.client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, eku)

        san = self.client.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        self.assertEqual(
            san.get_values_for_type(x509.UniformResourceIdentifier),
            ["urn:barbarika:demo:agent:primary-srv-01"],
        )

    def test_certificates_are_short_lived_and_currently_valid(self) -> None:
        for cert in (self.ca, self.server, self.client):
            span = cert.not_valid_after_utc - cert.not_valid_before_utc
            # not_valid_before is backdated one day for clock skew.
            self.assertLessEqual(span.days, VALIDITY_DAYS + 1)
            now = datetime.now(timezone.utc)
            self.assertLess(cert.not_valid_before_utc, now)
            self.assertGreater(cert.not_valid_after_utc, now)

    def test_refuses_overwrite_without_force(self) -> None:
        with self.assertRaises(DemoCertificatesExistError):
            generate_mtls_pki(self._tmp.name)

    def test_force_rotates_the_ca(self) -> None:
        before = _load(self.paths["ca_cert"]).serial_number
        generate_mtls_pki(self._tmp.name, force=True)
        after = _load(self.paths["ca_cert"]).serial_number
        self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
