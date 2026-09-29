"""Tests for the core modules added for Tasks 5-8: RSA-OAEP, hybrid, signatures, DH, hashing."""

from __future__ import annotations

import os

import pytest

from core import crypto_utils as cu
from core import diffie_hellman as dh
from core.hashing import digests_match, sha256_bytes
from core.hybrid import MAGIC, HybridPackage, hybrid_decrypt, hybrid_encrypt
from core.key_manager import export_public_key_pem, generate_rsa_keypair, public_key_fingerprint
from core.signatures import sign_pss, verify_pss
from Crypto.Util.number import isPrime


# ------------------------------------------------------------------ RSA / OAEP
def test_rsa_key_size_policy(rsa_key):
    assert rsa_key.size_in_bits() == 2048
    with pytest.raises(ValueError):
        generate_rsa_keypair(1024)


def test_public_export_contains_no_private_material(rsa_key):
    pem = export_public_key_pem(rsa_key)
    assert b"PUBLIC KEY" in pem and b"PRIVATE" not in pem
    assert public_key_fingerprint(rsa_key) == public_key_fingerprint(rsa_key.publickey())


def test_oaep_wrap_unwrap(rsa_key):
    secret = os.urandom(16)
    w1, w2 = cu.rsa_oaep_wrap(secret, rsa_key.publickey()), cu.rsa_oaep_wrap(secret, rsa_key)
    assert len(w1) == 256 and w1 != w2              # OAEP is randomised
    assert cu.rsa_oaep_unwrap(w1, rsa_key) == secret


def test_oaep_rejects_wrong_key_public_key_and_tampering(rsa_identities):
    right, wrong = rsa_identities["receiver"], rsa_identities["attacker"]
    wrapped = cu.rsa_oaep_wrap(b"k" * 16, right)
    with pytest.raises(ValueError):
        cu.rsa_oaep_unwrap(wrapped, wrong)
    with pytest.raises(ValueError):
        cu.rsa_oaep_unwrap(wrapped, right.publickey())
    with pytest.raises(ValueError):
        cu.rsa_oaep_unwrap(cu.flip_bit(wrapped, 100), right)


# -------------------------------------------------------------------- hybrid
@pytest.mark.parametrize("size", [0, 1, 15, 16, 190, 191, 100_000])
def test_hybrid_round_trip_any_size(rsa_key, size):
    """Sizes beyond RSA's 190-byte OAEP limit work because only the AES key goes through RSA."""
    data = os.urandom(size)
    package, _ = hybrid_encrypt(data, rsa_key.publickey())
    restored = HybridPackage.from_bytes(package.to_bytes())
    assert restored == package
    assert hybrid_decrypt(restored, rsa_key) == data


def test_hybrid_package_validation(rsa_key):
    blob = hybrid_encrypt(b"payload", rsa_key)[0].to_bytes()
    assert blob.startswith(MAGIC)
    for bad in (b"", b"NOTMAGIC" + blob[8:], blob[:-1], blob[:40]):
        with pytest.raises(ValueError):
            HybridPackage.from_bytes(bad)


def test_hybrid_wrong_receiver_cannot_decrypt(rsa_identities):
    package, _ = hybrid_encrypt(b"secret file", rsa_identities["receiver"])
    with pytest.raises(ValueError):
        hybrid_decrypt(package, rsa_identities["attacker"])


# ----------------------------------------------------------------- signatures
def test_pss_sign_verify(rsa_identities):
    key, other = rsa_identities["sender"], rsa_identities["attacker"]
    msg = b"student_records.txt digest"
    sig = sign_pss(msg, key)
    assert verify_pss(msg, sig, key.publickey())
    assert not verify_pss(msg + b"!", sig, key.publickey())
    assert not verify_pss(msg, sig, other.publickey())
    assert not verify_pss(msg, sig[:-1], key.publickey())
    with pytest.raises(ValueError):
        sign_pss(msg, key.publickey())


# ------------------------------------------------------------------------ DH
def test_dh_group_parameters():
    assert dh.P.bit_length() == 2048
    assert isPrime(dh.P) and isPrime(dh.Q)          # safe prime
    assert pow(dh.G, dh.Q, dh.P) == 1              # g generates the order-q subgroup


def test_dh_shared_secret_equality():
    a, b = dh.DHParty("Sender"), dh.DHParty("Receiver")
    assert a.shared_secret(b.public) == b.shared_secret(a.public)
    assert a.session_key(b.public) == b.session_key(a.public)
    assert len(a.session_key(b.public)) == 16
    c = dh.DHParty("Other")
    assert a.shared_secret(b.public) != a.shared_secret(c.public)


def test_dh_rejects_invalid_public_values():
    party = dh.DHParty("Receiver")
    non_subgroup = dh.P - 2
    assert pow(non_subgroup, dh.Q, dh.P) != 1
    for bad in (0, 1, dh.P - 1, dh.P, dh.P + 5, non_subgroup):
        with pytest.raises(ValueError):
            party.shared_secret(bad)


def test_dh_private_value_not_exposed(monkeypatch):
    monkeypatch.setattr(dh.secrets, "randbelow", lambda n: 0xDEADBEEF123)
    party = dh.DHParty("Sender")
    assert "deadbeef" not in repr(party).lower()
    assert party.private_bits == (0xDEADBEEF123 + 2).bit_length()


def test_digests_match():
    h = sha256_bytes(b"abc")
    assert digests_match(h, h.upper())
    assert not digests_match(h, sha256_bytes(b"abd"))
