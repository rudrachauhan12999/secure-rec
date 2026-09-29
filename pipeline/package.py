"""The transfer package: exactly what travels from Sender to Receiver.

Serialized as UTF-8 JSON (binary fields base64-encoded) so it can be
inspected in a file viewer or in Wireshark.  It contains ONLY:

    header                  format, algorithms, claimed sender, creation time,
                            fingerprint of the intended receiver's public key
    sender_certificate_pem  sender's X.509 certificate (public)
    wrapped_key             RSA-OAEP-SHA256(AES session key) for the receiver
    manifest_iv/ciphertext  AES-128-CBC({filename, type, size, sha256})
    payload_iv/ciphertext   AES-128-CBC(file bytes)
    signature               RSA-PSS-SHA256 over the signed structure below

It never contains the plaintext, the raw session key or any private key.
Because the manifest is encrypted, an eavesdropper does not even learn the
file name or its SHA-256 - only the approximate size.

Signed structure (canonical JSON: sorted keys, no whitespace)::

    {
      "format": "SECURE-REC-PKG/1",
      "header": {...},
      "sender_certificate_sha256": SHA-256(certificate DER),
      "wrapped_key_sha256":        SHA-256(wrapped_key),
      "manifest_iv":               hex,
      "manifest_ciphertext_sha256": SHA-256(manifest ciphertext),
      "payload_iv":                hex,
      "payload_ciphertext_sha256": SHA-256(payload ciphertext)
    }

Every transmitted field is therefore covered by the signature, directly or
via its hash, and the receiver can reject a modified package *before*
decrypting anything.  The plaintext SHA-256 is inside the encrypted
manifest, so after decryption it is authenticated as well.
"""

from __future__ import annotations

import base64
import binascii
import json
import ssl
from dataclasses import dataclass, field

from core.hashing import sha256_bytes

FORMAT = "SECURE-REC-PKG/1"
_BINARY_FIELDS = ("wrapped_key", "manifest_iv", "manifest_ciphertext", "payload_iv", "payload_ciphertext",
                  "signature")


class PackageFormatError(ValueError):
    """The received bytes are not a well-formed transfer package."""


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def certificate_fingerprint(cert_pem: str) -> str:
    """SHA-256 of the certificate's DER encoding (the value that gets pinned)."""
    return sha256_bytes(ssl.PEM_cert_to_DER_cert(cert_pem))


@dataclass
class TransferPackage:
    header: dict
    sender_certificate_pem: str
    wrapped_key: bytes
    manifest_iv: bytes
    manifest_ciphertext: bytes
    payload_iv: bytes
    payload_ciphertext: bytes
    signature: bytes = field(default=b"")

    def signed_structure(self) -> dict:
        return {
            "format": FORMAT,
            "header": self.header,
            "sender_certificate_sha256": certificate_fingerprint(self.sender_certificate_pem),
            "wrapped_key_sha256": sha256_bytes(self.wrapped_key),
            "manifest_iv": self.manifest_iv.hex(),
            "manifest_ciphertext_sha256": sha256_bytes(self.manifest_ciphertext),
            "payload_iv": self.payload_iv.hex(),
            "payload_ciphertext_sha256": sha256_bytes(self.payload_ciphertext),
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.signed_structure())

    def to_bytes(self) -> bytes:
        doc = {"format": FORMAT, "header": self.header, "sender_certificate_pem": self.sender_certificate_pem}
        doc.update({name: base64.b64encode(getattr(self, name)).decode() for name in _BINARY_FIELDS})
        return json.dumps(doc, indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, blob: bytes) -> "TransferPackage":
        try:
            doc = json.loads(blob.decode("utf-8"))
            if doc.get("format") != FORMAT:
                raise PackageFormatError(f"unsupported package format {doc.get('format')!r}")
            binary = {name: base64.b64decode(doc[name], validate=True) for name in _BINARY_FIELDS}
            return cls(header=dict(doc["header"]), sender_certificate_pem=str(doc["sender_certificate_pem"]),
                       **binary)
        except PackageFormatError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError,
                binascii.Error) as exc:
            raise PackageFormatError(f"malformed transfer package: {type(exc).__name__}") from None
