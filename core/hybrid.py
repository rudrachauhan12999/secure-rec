"""RSA + AES hybrid encryption (reused by Task 5 and the integrated pipeline).

Sender:   random AES-128 session key K
          C  = AES-128-CBC_K(file)            (bulk data, fast)
          WK = RSA-OAEP_{receiver public}(K)  (only 16 bytes go through RSA)
Receiver: K  = RSA-OAEP^-1_{receiver private}(WK)
          file = AES-128-CBC^-1_K(C)

Package format written to disk / sent over the wire (all fields public)::

    MAGIC (8) | len(WK) (2, big-endian) | WK | IV (16) | ciphertext
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from Crypto.PublicKey import RSA

from core import crypto_utils as cu
from core.key_manager import generate_aes_key

MAGIC = b"SRECHYB1"


@dataclass(frozen=True)
class HybridPackage:
    wrapped_key: bytes
    iv: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return MAGIC + struct.pack(">H", len(self.wrapped_key)) + self.wrapped_key + self.iv + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "HybridPackage":
        header = len(MAGIC) + 2
        if len(blob) < header or not blob.startswith(MAGIC):
            raise ValueError("Not a SECURE-REC hybrid package")
        (wk_len,) = struct.unpack(">H", blob[len(MAGIC):header])
        body = blob[header:]
        if len(body) < wk_len + 2 * cu.AES_BLOCK or (len(body) - wk_len) % cu.AES_BLOCK:
            raise ValueError("Truncated or malformed hybrid package")
        return cls(body[:wk_len], body[wk_len:wk_len + cu.AES_BLOCK], body[wk_len + cu.AES_BLOCK:])


def hybrid_encrypt(plaintext: bytes, receiver_public_key: RSA.RsaKey) -> tuple[HybridPackage, bytes]:
    """Return the package and the session key (the key is returned only so a
    demonstration can show its fingerprint; it must never be transmitted)."""
    session_key = generate_aes_key(128)
    iv, ciphertext = cu.aes_cbc_encrypt(plaintext, session_key)
    wrapped = cu.rsa_oaep_wrap(session_key, receiver_public_key)
    return HybridPackage(wrapped, iv, ciphertext), session_key


def unwrap_session_key(package: HybridPackage, receiver_private_key: RSA.RsaKey) -> bytes:
    return cu.rsa_oaep_unwrap(package.wrapped_key, receiver_private_key)


def hybrid_decrypt(package: HybridPackage, receiver_private_key: RSA.RsaKey) -> bytes:
    session_key = unwrap_session_key(package, receiver_private_key)
    return cu.aes_cbc_decrypt(package.ciphertext, session_key, package.iv)
