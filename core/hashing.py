"""SHA-256 helpers (hashlib, i.e. OpenSSL-backed)."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

_CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digests_match(a: str, b: str) -> bool:
    """Compare two hex digests in constant time (habit that matters for MACs)."""
    return hmac.compare_digest(a.lower(), b.lower())


def sha256_file(path: str | Path) -> str:
    """Stream the file so large inputs are not loaded twice."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()
