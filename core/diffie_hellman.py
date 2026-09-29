"""Finite-field Diffie-Hellman (educational) over the RFC 3526 2048-bit MODP group.

    public parameters: prime p, generator g = 2
    each party:        private x (random), public X = g^x mod p
    shared secret:     S = Y^x mod p  (= g^(xy) mod p on both sides)
    session key:       HKDF-SHA256(S) -> 16-byte AES-128 key

An eavesdropper sees p, g, X and Y but recovering S requires solving the
discrete-logarithm problem.  Plain DH does NOT authenticate who sent X or Y,
which is exactly what the man-in-the-middle attack (Task 7) exploits.

The arithmetic uses Python's ``pow`` (not constant-time) - fine for a
demonstration, not for production.  Real systems use vetted TLS/ECDHE
implementations.
"""

from __future__ import annotations

import secrets

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from core.key_manager import key_fingerprint

# RFC 3526, section 3: 2048-bit MODP Group (group 14). p is a safe prime,
# p = 2q + 1 with q prime, and g = 2 generates the subgroup of order q.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
Q = (P - 1) // 2
GROUP_NAME = "RFC 3526 MODP group 14 (2048-bit)"
BYTE_LEN = (P.bit_length() + 7) // 8  # 256
HKDF_CONTEXT = b"SECURE-REC DH session key v1"


def validate_public_value(y: int) -> None:
    """Reject values that would force a weak/predictable shared secret.

    1 < y < p-1 rules out the trivial values 0, 1 and p-1; ``y^q mod p == 1``
    checks membership in the prime-order subgroup (small-subgroup attacks).
    """
    if not 1 < y < P - 1 or pow(y, Q, P) != 1:
        raise ValueError("Invalid Diffie-Hellman public value")


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes(BYTE_LEN, "big")


def derive_session_key(shared_secret: int, key_len: int = 16) -> bytes:
    """Never use the raw DH value as a key - pass it through a KDF first."""
    return HKDF(int_to_bytes(shared_secret), key_len, salt=None, hashmod=SHA256, context=HKDF_CONTEXT)


def short_hex(n: int, digits: int = 12) -> str:
    """Abbreviated view of a large public number for display."""
    h = format(n, "x")
    return f"{h[:digits]}...{h[-digits:]} ({n.bit_length()} bits)"


class DHParty:
    """One participant. The private exponent is kept in a private attribute
    and is never included in ``repr`` or any report."""

    def __init__(self, name: str):
        self.name = name
        self.__x = secrets.randbelow(Q - 2) + 2  # uniform in [2, q-1], OS CSPRNG
        self.public = pow(G, self.__x, P)

    def __repr__(self) -> str:
        return f"DHParty({self.name!r}, public={short_hex(self.public)})"

    @property
    def private_bits(self) -> int:
        """Size of the secret exponent - safe to display, the value is not."""
        return self.__x.bit_length()

    def shared_secret(self, peer_public: int) -> int:
        validate_public_value(peer_public)
        return pow(peer_public, self.__x, P)

    def session_key(self, peer_public: int) -> bytes:
        return derive_session_key(self.shared_secret(peer_public))


def secret_fingerprint(shared_secret: int) -> str:
    """Display-safe identifier of a shared secret (it is not the secret)."""
    return key_fingerprint(int_to_bytes(shared_secret))
