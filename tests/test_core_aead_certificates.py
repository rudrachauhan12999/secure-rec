"""Core additions for Tasks 9-12: AES-GCM and the OpenSSL certificate helpers."""

from __future__ import annotations

import os

import pytest

from core import certificates as certs
from core import crypto_utils as cu
from core.key_manager import generate_aes_key


# ----------------------------------------------------------------- AES-GCM
def test_gcm_round_trip_and_fresh_nonce():
    key, data = generate_aes_key(), os.urandom(1000)
    b1, b2 = cu.aes_gcm_encrypt(data, key, b"label"), cu.aes_gcm_encrypt(data, key, b"label")
    assert b1 != b2 and b1[:12] != b2[:12]
    assert len(b1) == 12 + len(data) + 16
    assert cu.aes_gcm_decrypt(b1, key, b"label") == data


@pytest.mark.parametrize("position", [0, 20, -1])  # nonce, ciphertext, tag
def test_gcm_detects_modification(position):
    key = generate_aes_key()
    blob = bytearray(cu.aes_gcm_encrypt(b"x" * 64, key))
    blob[position] ^= 0x01
    with pytest.raises(ValueError):
        cu.aes_gcm_decrypt(bytes(blob), key)


def test_gcm_wrong_key_aad_or_short_input():
    key = generate_aes_key()
    blob = cu.aes_gcm_encrypt(b"ticket", key, b"ticket|svc")
    for args in ((blob, generate_aes_key(), b"ticket|svc"), (blob, key, b"ticket|other"), (b"short", key, b"")):
        with pytest.raises(ValueError):
            cu.aes_gcm_decrypt(*args)


# ----------------------------------------------------------- certificates
def test_build_subject_escapes_slashes():
    assert certs.build_subject({"C": "IN", "CN": "a/b"}) == "/C=IN/CN=a\\/b"


def test_openssl_not_found(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENSSL_BIN", str(tmp_path / "missing.exe"))
    monkeypatch.setattr(certs.shutil, "which", lambda name: None)
    monkeypatch.setattr(certs, "_WINDOWS_CANDIDATES", [])
    with pytest.raises(certs.OpenSSLNotFound):
        certs.find_openssl()


def test_write_private_key_rejects_public_key(rsa_key, tmp_path):
    with pytest.raises(ValueError):
        certs.write_private_key(rsa_key.publickey(), tmp_path / "k.pem")


@pytest.fixture
def certificate(tmp_path, rsa_key):
    try:
        certs.find_openssl()
    except certs.OpenSSLNotFound:
        pytest.skip("OpenSSL not installed")
    key_path = certs.write_private_key(rsa_key, tmp_path / "keys" / "k.pem")
    subject = {"C": "IN", "O": "Test Org", "CN": "Unit Test Sender"}
    return certs.create_self_signed_certificate(key_path, tmp_path / "cert.pem", subject, days=30)


def test_certificate_fields(certificate, rsa_key):
    info = certs.inspect_certificate(certificate)
    assert "CN=Unit Test Sender" in info.subject and info.self_signed
    assert info.public_key_bits == 2048 and info.public_key_algorithm == "rsaEncryption"
    assert info.signature_algorithm == "sha256WithRSAEncryption"
    assert info.not_before and info.not_after and len(info.signature_hex_prefix) == 32
    assert not info.is_ca
    pub = certs.certificate_public_key(certificate)
    assert (pub.n, pub.e) == (rsa_key.n, rsa_key.e)


def test_certificate_verification_and_tampering(certificate, tmp_path):
    assert certs.verify_self_signed(certificate)[0]
    assert certs.is_currently_valid(certificate)
    ok, msg = certs.verify_certificate_signature(certificate, certificate, tmp_path / "work")
    assert ok and "Verified OK" in msg

    der = certs.pem_to_der(certificate, tmp_path / "c.der").read_bytes()
    tbs, sig = certs.split_certificate(der)
    assert len(sig) == 256 and tbs in der

    bad = bytearray(der)
    bad[der.rfind(b"Unit Test Sender")] ^= 0x07      # modify the Subject CN
    bad_der = tmp_path / "bad.der"
    bad_der.write_bytes(bytes(bad))
    bad_pem = certs.der_to_pem(bad_der, tmp_path / "bad.pem")
    assert not certs.verify_certificate_signature(bad_pem, certificate, tmp_path / "work")[0]
    assert not certs.verify_against_anchor(bad_pem, certificate)[0]
