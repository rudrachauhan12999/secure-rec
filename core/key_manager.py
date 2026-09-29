"""Runtime generation of symmetric keys and IVs.

Key-handling policy
-------------------
* No key is ever hard-coded: all keys come from ``get_random_bytes``, which
  draws from the operating system's CSPRNG.
* Symmetric keys for the demonstrations live only in memory for the duration
  of a run.  Reports show a *fingerprint* (truncated SHA-256 of the key) so two
  runs can be told apart without revealing the key itself.
* IVs are not secret: they are generated fresh for every encryption and
  stored in clear in front of the ciphertext.  What matters is that they are
  unpredictable and never reused with the same key.
"""

from __future__ import annotations

import hashlib

from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

AES_128_KEY_BYTES = 16
TDES_KEY_BYTES = 24  # three independent 56-bit DES keys (+ parity bits)


def generate_aes_key(bits: int = 128) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256 bits")
    return get_random_bytes(bits // 8)


def generate_3des_key() -> bytes:
    """Three-key 3-DES (K1, K2, K3 independent).

    ``adjust_key_parity`` fixes the DES parity bits and rejects keys that
    would make 3-DES degenerate to single DES (K1 == K2 or K2 == K3); in that
    astronomically unlikely case we simply draw again.
    """
    while True:
        try:
            return DES3.adjust_key_parity(get_random_bytes(TDES_KEY_BYTES))
        except ValueError:
            continue


def generate_iv(block_size: int = AES.block_size) -> bytes:
    """Fresh, unpredictable IV: 16 bytes for AES, 8 bytes for DES/3-DES."""
    return get_random_bytes(block_size)


def key_fingerprint(key: bytes) -> str:
    """Short non-reversible identifier for a key, safe to display or log."""
    return hashlib.sha256(key).hexdigest()[:16]


# ------------------------------------------------------------------------ RSA
RSA_KEY_BITS = 2048


def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> RSA.RsaKey:
    """Generate an RSA private key (its ``.publickey()`` is the public half).

    Private keys generated here stay in memory; callers export only the
    public key unless a later task explicitly needs persistent key files.
    """
    if bits < 2048:
        raise ValueError("RSA keys shorter than 2048 bits are not accepted")
    return RSA.generate(bits)


def public_key_fingerprint(key: RSA.RsaKey) -> str:
    """Fingerprint of the *public* half (SHA-256 of its DER encoding)."""
    return key_fingerprint(key.publickey().export_key(format="DER"))


def export_public_key_pem(key: RSA.RsaKey) -> bytes:
    return key.publickey().export_key(format="PEM")
