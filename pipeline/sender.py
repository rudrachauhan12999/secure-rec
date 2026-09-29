"""Sender side of the integrated pipeline (reuses core crypto only)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from Crypto.PublicKey import RSA

from core import certificates as certs
from core import crypto_utils as cu
from core.file_handler import FileInfo
from core.hashing import sha256_bytes
from core.hybrid import hybrid_encrypt
from core.key_manager import generate_rsa_keypair, key_fingerprint, public_key_fingerprint
from core.signatures import sign_pss
from pipeline.package import FORMAT, TransferPackage, canonical_json

SENDER_SUBJECT = {
    "C": "IN",
    "O": "SECURE-REC Educational Demo",
    "OU": "Integrated Pipeline",
    "CN": "SECURE-REC Sender",
}
CERT_VALIDITY_DAYS = 365

ALGORITHMS = {
    "file_encryption": "AES-128-CBC, PKCS#7, random 16-byte IV",
    "key_protection": "RSA-2048 OAEP (SHA-256)",
    "signature": "RSA-PSS (SHA-256)",
    "integrity": "SHA-256",
    "certificate": "X.509 v3, self-signed (educational), sha256WithRSAEncryption",
}


@dataclass
class SenderIdentity:
    key: RSA.RsaKey            # private signing key - memory + keys/ only
    certificate_pem: str
    certificate_path: Path
    common_name: str


def create_sender_identity(keys_dir: Path, cert_dir: Path, key: RSA.RsaKey | None = None,
                           subject: dict[str, str] | None = None) -> SenderIdentity:
    """Signing key pair + self-signed certificate (the Task 11 mechanism, core.certificates).

    OpenSSL needs the private key as a file to self-sign, so it is written to
    ``keys_dir`` (git-ignored) - never to outputs/.
    """
    key = key or generate_rsa_keypair()
    subject = subject or SENDER_SUBJECT
    key_path = certs.write_private_key(key, keys_dir / "sender_private_key.pem")
    cert_path = certs.create_self_signed_certificate(key_path, cert_dir / "sender_certificate.pem",
                                                     subject, CERT_VALIDITY_DAYS)
    return SenderIdentity(key, cert_path.read_text(encoding="utf-8"), cert_path, subject["CN"])


def build_manifest(info: FileInfo, data: bytes) -> dict:
    """File metadata, including the reference SHA-256. Sent encrypted."""
    return {"filename": info.name, "type": info.type_label, "size": len(data), "sha256": sha256_bytes(data)}


def seal_package(data: bytes, manifest: dict, identity: SenderIdentity,
                 receiver_public: RSA.RsaKey) -> tuple[TransferPackage, str]:
    """Encrypt, protect the key, sign.  Returns the package and the session-key
    *fingerprint* (the key itself goes out of scope here and is never stored)."""
    hybrid, session_key = hybrid_encrypt(data, receiver_public)          # AES-128-CBC + RSA-OAEP
    manifest_iv, manifest_ct = cu.aes_cbc_encrypt(canonical_json(manifest), session_key)
    header = {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sender": identity.common_name,
        "receiver_key_fingerprint": public_key_fingerprint(receiver_public),
        "algorithms": ALGORITHMS,
        "format": FORMAT,
    }
    package = TransferPackage(header, identity.certificate_pem, hybrid.wrapped_key, manifest_iv, manifest_ct,
                              hybrid.iv, hybrid.ciphertext)
    package.signature = sign_pss(package.signed_bytes(), identity.key)  # sign the whole structure
    return package, key_fingerprint(session_key)
