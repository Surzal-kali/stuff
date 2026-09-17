"""Tests for auxiliaries.cert_tools — the certificate INSPECTION family.

The critical property under test: ``spki_sha1_b64`` equals the value an
INDEPENDENT implementation (the openssl CLI pipeline) computes for the same
cert, because that field is the OkHttp CertificatePinner pin format and any
drift here poisons every pin comparison the framework makes.

Live-network behavior (inspect_host) is deliberately NOT covered here —
tests must stay zero-traffic. The live acceptance test is run manually
against a known-good in-scope host (e.g. grindr.mobi must reproduce the
banked baseline pin).
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from auxiliaries.cert_tools import _cert_fields, inspect_pem


def _make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(key, not_before, not_after, cn="test.local", sans=("test.local", "alt.test.local")):
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


@pytest.fixture(scope="module")
def cert_pem_text():
    key = _make_key()
    now = datetime.now(timezone.utc)
    cert = _make_cert(key, now - timedelta(hours=1), now + timedelta(days=30))
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def _expected_spki_sha1_b64(pem_text: str) -> str:
    """Independent oracle via the openssl CLI pipeline, if openssl exists."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    proc = subprocess.run(
        "openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER "
        "| openssl dgst -sha1 -binary | base64",
        input=pem_text,
        capture_output=True,
        text=True,
        shell=True,
        check=True,
    )
    return proc.stdout.strip()


def test_spki_sha1_matches_independent_openssl(cert_pem_text):
    """THE acceptance property: pin-format hash agrees with openssl."""
    result = inspect_pem(cert_pem_text)
    assert result["status"] == "ok"
    assert result["spki_sha1_b64"] == _expected_spki_sha1_b64(cert_pem_text)


def test_input_parity_pem_der_path(cert_pem_text, tmp_path):
    """PEM text, base64 DER, and file path must yield identical FIELDS
    (the ``source`` label is allowed to differ by design)."""
    cert_file = tmp_path / "c.pem"
    cert_file.write_text(cert_pem_text)

    der = x509.load_pem_x509_certificate(cert_pem_text.encode()).public_bytes(Encoding.DER)
    r_path = inspect_pem(str(cert_file))
    r_pem = inspect_pem(cert_pem_text)
    r_der = inspect_pem(base64.b64encode(der).decode())

    for r in (r_path, r_pem, r_der):
        assert r["status"] == "ok"
    assert r_path["source"] == "file:pem"
    assert r_pem["source"] == "pem"
    assert r_der["source"] == "der"
    # Field-set parity (ignore the source label)
    f_path = {k: v for k, v in r_path.items() if k != "source"}
    f_pem = {k: v for k, v in r_pem.items() if k != "source"}
    f_der = {k: v for k, v in r_der.items() if k != "source"}
    assert f_path == f_pem == f_der


def test_field_extraction_shape(cert_pem_text):
    result = inspect_pem(cert_pem_text)
    assert result["subject"].startswith("CN=")
    assert result["sans_dns"] == ["test.local", "alt.test.local"]
    assert result["key_type"] == "RSAPublicKey"
    assert result["key_bits"] == 2048
    assert result["days_remaining"] > 29  # 30-day cert, signed an hour ago
    assert result["sha1_cert_fp_b64"] != result["spki_sha1_b64"]  # different DER envelopes
    assert len(base64.b64decode(result["sha256_cert_fp_b64"])) == 32
    assert len(base64.b64decode(result["spki_sha256_b64"])) == 32


def test_expired_cert_reports_negative_days():
    key = _make_key()
    now = datetime.now(timezone.utc)
    cert = _make_cert(key, now - timedelta(days=40), now - timedelta(days=10))
    der = cert.public_bytes(Encoding.DER)
    fields = _cert_fields(der)
    assert fields["days_remaining"] < 0
    assert -10.5 < fields["days_remaining"] <= -9.5


def test_cert_without_sans():
    key = _make_key()
    now = datetime.now(timezone.utc)
    cert = _make_cert(key, now - timedelta(hours=1), now + timedelta(days=1), sans=())
    result = inspect_pem(cert.public_bytes(Encoding.PEM).decode("ascii"))
    assert result["status"] == "ok"
    assert result["sans_dns"] == []


def test_error_paths():
    assert inspect_pem("")["status"] == "error"
    assert inspect_pem("this is not a certificate")["status"] == "error"
    assert inspect_pem("AAAA")["status"] == "error"  # b64-valid but not DER cert parse
    # nonexistent file path that can't be b64 either
    assert inspect_pem("/nonexistent/path/nope.pem")["status"] == "error"