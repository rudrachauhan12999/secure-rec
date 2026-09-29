"""Task 11: X.509 certificate via OpenSSL."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from Crypto.PublicKey import RSA

from core import certificates as certs
from core.config import PROJECT_ROOT
from core.results import Status
from tasks import task11_certificate as t11


@pytest.fixture(autouse=True)
def _require_openssl():
    try:
        certs.find_openssl()
    except certs.OpenSSLNotFound:
        pytest.skip("OpenSSL not installed")


@pytest.fixture
def cert_run(tmp_path, out_root, rsa_key, sample_file):
    keys_dir = tmp_path / "keys" / "task11"
    result = t11.run(sample_file, output_root=out_root, keys_dir=keys_dir, sender_key=rsa_key)
    return result, out_root / "task11", keys_dir


def test_certificate_generated_and_verified(cert_run):
    result, out, _ = cert_run
    assert result.status is Status.PASS, result.reason
    d = result.data
    assert "CN=SECURE-REC Sender" in d["subject"] and d["subject"] == d["issuer"] and d["self_signed"]
    assert d["public_key_bits"] == 2048 and d["signature_algorithm"] == "sha256WithRSAEncryption"
    assert d["verified"] and d["tbs_signature_valid"] and d["currently_valid"] and d["key_matches"]
    assert d["tampered_subject_rejected"] and d["tampered_signature_rejected"]
    assert d["file_signature_verified_with_cert"]
    for f in ("sender_certificate.pem", "sender_certificate.der", "certificate_info.txt"):
        assert (out / f).exists()


def test_report_shows_required_fields_and_disclaimer(cert_run):
    _, out, _ = cert_run
    text = (out / "report.txt").read_text()
    for needle in ("Subject", "Issuer", "Public key", "Validity: not before", "Validity: not after",
                   "Signature", "self-signed", "no trusted CA"):
        assert needle in text
    assert "Hacker" in certs.inspect_certificate(out / "tampered_subject_certificate.pem").subject


def test_private_key_only_in_keys_dir(cert_run, rsa_key):
    _, out, keys_dir = cert_run
    for f in out.rglob("*"):
        if f.is_file():
            assert b"PRIVATE KEY" not in f.read_bytes(), f
    stored = RSA.import_key((keys_dir / "sender_private_key.pem").read_bytes())
    assert stored.has_private() and stored.n == rsa_key.n


def test_openssl_missing_is_reported(monkeypatch, sample_file, out_root, tmp_path):
    def missing():
        raise certs.OpenSSLNotFound("OpenSSL executable not found")
    monkeypatch.setattr(certs, "find_openssl", missing)
    result = t11.run(sample_file, output_root=out_root, keys_dir=tmp_path / "k")
    assert result.status is Status.ERROR and "OpenSSL" in result.reason


def test_gitignore_excludes_generated_keys(tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("git not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(PROJECT_ROOT / ".gitignore", repo / ".gitignore")
    subprocess.run([git, "init", "-q"], cwd=repo, check=True)
    for path in ("keys/task11/sender_private_key.pem", "outputs/task11/sender_certificate.pem", "any/x.key"):
        proc = subprocess.run([git, "check-ignore", "-q", path], cwd=repo)
        assert proc.returncode == 0, f"{path} is not git-ignored"
    assert subprocess.run([git, "check-ignore", "-q", "keys/.gitkeep"], cwd=repo).returncode == 1
