"""Thin, well-documented wrappers around PyCryptodome block ciphers.

All actual cryptography is done by PyCryptodome; these helpers only fix the
conventions used throughout the project:

* Padding: PKCS#7 (AES block = 16 bytes, DES/3-DES block = 8 bytes).
* Container format for CBC files: ``IV || ciphertext``.  The IV is public
  and must travel with the ciphertext so the receiver can decrypt.
* CBC chaining: C_i = E_K(P_i XOR C_{i-1}), with C_0 = IV.

Note on authentication: CBC provides *confidentiality only*.  An attacker
can modify CBC ciphertext without knowing the key; detecting that requires
a hash/MAC/signature (later tasks) or an AEAD mode such as AES-GCM.
"""

from __future__ import annotations

from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

from core.key_manager import generate_iv

AES_BLOCK = AES.block_size    # 16
TDES_BLOCK = DES3.block_size  # 8


# --------------------------------------------------------------------- AES-CBC
def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(iv, ciphertext)``.

    ``iv`` should normally be left as ``None`` so a fresh random IV is drawn.
    Supplying a fixed IV exists only for controlled experiments (Task 2).
    """
    iv = iv if iv is not None else generate_iv(AES_BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plaintext, AES_BLOCK))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK)


# --------------------------------------------------------------------- AES-ECB
def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """ECB: every 16-byte block is encrypted independently with the same key.

    Identical plaintext blocks therefore give identical ciphertext blocks -
    ECB is included only to demonstrate that weakness (Task 3).
    """
    return AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, AES_BLOCK))


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES_BLOCK)


def aes_encrypt_single_block(block: bytes, key: bytes) -> bytes:
    """Apply the raw AES permutation to exactly one 16-byte block (no mode, no padding)."""
    if len(block) != AES_BLOCK:
        raise ValueError("AES block must be exactly 16 bytes")
    return AES.new(key, AES.MODE_ECB).encrypt(block)


# ------------------------------------------------------------------- 3-DES-CBC
def tdes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    iv = iv if iv is not None else generate_iv(TDES_BLOCK)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plaintext, TDES_BLOCK))


def tdes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), TDES_BLOCK)


# ----------------------------------------------------------- AES-GCM (AEAD)
GCM_NONCE = 12
GCM_TAG = 16


def aes_gcm_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Authenticated encryption: returns ``nonce || ciphertext || tag``.

    Unlike CBC, GCM detects any modification: decryption fails if the
    ciphertext, nonce, tag or associated data (``aad``) were altered.
    ``aad`` is authenticated but not encrypted (e.g. a message-type label).
    """
    nonce = generate_iv(GCM_NONCE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ct + tag


def aes_gcm_decrypt(blob: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Raises ``ValueError`` if the data or key is wrong (authentication failure)."""
    if len(blob) < GCM_NONCE + GCM_TAG:
        raise ValueError("AES-GCM blob too short")
    nonce, ct, tag = blob[:GCM_NONCE], blob[GCM_NONCE:-GCM_TAG], blob[-GCM_TAG:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


# ------------------------------------------------------------------- RSA-OAEP
def rsa_oaep_wrap(secret: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypt a short secret (e.g. an AES session key) with RSA-OAEP/SHA-256.

    OAEP adds randomised padding, so wrapping the same key twice gives
    different outputs.  RSA can only encrypt a few hundred bytes (190 bytes
    for a 2048-bit key with SHA-256), which is why whole files are encrypted
    with AES and only the AES key goes through RSA (hybrid encryption).
    """
    return PKCS1_OAEP.new(public_key.publickey(), hashAlgo=SHA256).encrypt(secret)


def rsa_oaep_unwrap(wrapped: bytes, private_key: RSA.RsaKey) -> bytes:
    """Recover the secret; raises ``ValueError`` for a wrong key or altered data."""
    if not private_key.has_private():
        raise ValueError("RSA private key required to unwrap")
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(wrapped)


# ------------------------------------------------------------ IV || ciphertext
def pack_iv_ciphertext(iv: bytes, ciphertext: bytes) -> bytes:
    return iv + ciphertext


def unpack_iv_ciphertext(blob: bytes, block_size: int) -> tuple[bytes, bytes]:
    if len(blob) < 2 * block_size or (len(blob) - block_size) % block_size:
        raise ValueError("Malformed IV||ciphertext container")
    return blob[:block_size], blob[block_size:]


# ------------------------------------------------------------------ bit tools
def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Return a copy of ``data`` with exactly one bit inverted.

    Bits are numbered from the most significant bit of byte 0, i.e. bit 0 is
    ``0x80`` of the first byte and bit 7 is ``0x01`` of the first byte.
    """
    if not 0 <= bit_index < len(data) * 8:
        raise IndexError("bit_index outside data")
    buf = bytearray(data)
    buf[bit_index // 8] ^= 0x80 >> (bit_index % 8)
    return bytes(buf)


def count_differing_bits(a: bytes, b: bytes) -> int:
    """Hamming distance between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("inputs must have equal length")
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big").bit_count()
