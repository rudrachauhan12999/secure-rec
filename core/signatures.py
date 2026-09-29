"""RSA-PSS digital signatures over SHA-256 (PyCryptodome).

sign:   s = RSA-PSS_{private}(SHA-256(message))
verify: accept only if s matches SHA-256(message) under the signer's public key.

A signature provides integrity *and* authentication (only the private-key
holder could produce it); a bare hash provides integrity only, because anyone
can recompute a hash for modified data.
"""

from __future__ import annotations

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def sign_pss(message: bytes, private_key: RSA.RsaKey) -> bytes:
    if not private_key.has_private():
        raise ValueError("RSA private key required to sign")
    return pss.new(private_key).sign(SHA256.new(message))


def verify_pss(message: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    try:
        pss.new(public_key.publickey()).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False
