"""Receiver side of the integrated pipeline.

``receive_package`` runs the checks in a fixed order and STOPS at the first
failure - a package is never partially accepted and nothing is repaired:

  1. Package format        well-formed SECURE-REC-PKG/1 document
  2. Certificate           OpenSSL: self-signature valid, within validity period
  3. Sender identity       certificate fingerprint == pinned trusted fingerprint
                           (for a self-signed certificate this pinning is the
                           ONLY thing that ties the key to the sender)
  4. Digital signature     RSA-PSS over the signed structure, using the public
                           key taken from the verified certificate
  5. RSA key recovery      package addressed to our key; RSA-OAEP unwrap
  6. AES decryption        manifest + file, AES-128-CBC
  7. SHA-256 integrity     SHA-256(recovered) == reference hash in the manifest

Used both in-process (secure_pipeline) and by the TCP network demo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from Crypto.PublicKey import RSA

from core import certificates as certs
from core import crypto_utils as cu
from core.hashing import digests_match, sha256_bytes
from core.key_manager import key_fingerprint, public_key_fingerprint
from core.signatures import verify_pss
from pipeline.package import PackageFormatError, TransferPackage, certificate_fingerprint

STAGE_FORMAT = "Package format"
STAGE_CERT = "Certificate verification"
STAGE_IDENTITY = "Sender identity (pinned certificate)"
STAGE_SIGNATURE = "Digital signature"
STAGE_KEY = "RSA key recovery"
STAGE_DECRYPT = "AES decryption"
STAGE_INTEGRITY = "SHA-256 integrity"
RECEIVER_STAGES = [STAGE_FORMAT, STAGE_CERT, STAGE_IDENTITY, STAGE_SIGNATURE, STAGE_KEY, STAGE_DECRYPT,
                   STAGE_INTEGRITY]


@dataclass
class TrustStore:
    """What the receiver trusts, established out of band before any transfer."""
    sender_cn: str
    certificate_sha256: str

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"trusted_sender": {"common_name": self.sender_cn,
                                                       "certificate_sha256": self.certificate_sha256}},
                                   indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "TrustStore":
        entry = json.loads(path.read_text(encoding="utf-8"))["trusted_sender"]
        return cls(entry["common_name"], entry["certificate_sha256"])


@dataclass
class StageResult:
    stage: str
    ok: bool
    detail: str


@dataclass
class ReceiverOutcome:
    stages: list[StageResult] = field(default_factory=list)
    accepted: bool = False
    recovered: bytes | None = None
    manifest: dict | None = None
    certificate: certs.CertificateInfo | None = None

    @property
    def failed_stage(self) -> str | None:
        return next((s.stage for s in self.stages if not s.ok), None)

    def stage(self, name: str) -> StageResult | None:
        return next((s for s in self.stages if s.stage == name), None)


def receive_package(blob: bytes, receiver_key: RSA.RsaKey, trust: TrustStore, work_dir: Path) -> ReceiverOutcome:
    out = ReceiverOutcome()

    def passed(stage: str, detail: str) -> None:
        out.stages.append(StageResult(stage, True, detail))

    def failed(stage: str, detail: str) -> ReceiverOutcome:
        out.stages.append(StageResult(stage, False, detail))
        return out

    # 1. format
    try:
        pkg = TransferPackage.from_bytes(blob)
        cert_fp = certificate_fingerprint(pkg.sender_certificate_pem)
    except (PackageFormatError, ValueError) as exc:
        return failed(STAGE_FORMAT, str(exc))
    passed(STAGE_FORMAT, f"{len(blob)} bytes, {pkg.header.get('format')}")

    # 2. certificate (OpenSSL)
    work_dir.mkdir(parents=True, exist_ok=True)
    cert_path = work_dir / "received_sender_certificate.pem"
    cert_path.write_text(pkg.sender_certificate_pem, encoding="utf-8")
    try:
        sig_ok, msg = certs.verify_self_signed(cert_path)
        in_date = certs.is_currently_valid(cert_path)
        out.certificate = certs.inspect_certificate(cert_path)
    except certs.OpenSSLError as exc:
        return failed(STAGE_CERT, f"certificate unreadable: {exc}")
    if not sig_ok:
        return failed(STAGE_CERT, f"OpenSSL rejected the certificate ({msg})")
    if not in_date:
        return failed(STAGE_CERT, "certificate is expired or not yet valid")
    passed(STAGE_CERT, f"self-signature valid, in validity period; subject {out.certificate.subject}")

    # 3. identity: self-signed => trust only the pinned certificate
    if not digests_match(cert_fp, trust.certificate_sha256):
        return failed(STAGE_IDENTITY, f"certificate fingerprint {cert_fp[:16]}... is NOT the trusted sender "
                                      f"certificate {trust.certificate_sha256[:16]}...")
    if f"CN={trust.sender_cn}" not in out.certificate.subject:
        return failed(STAGE_IDENTITY, f"certificate subject does not name {trust.sender_cn}")
    passed(STAGE_IDENTITY, f"fingerprint matches pinned certificate for {trust.sender_cn}")

    # 4. signature with the public key from the verified certificate
    sender_public = certs.certificate_public_key(cert_path)
    if not verify_pss(pkg.signed_bytes(), pkg.signature, sender_public):
        return failed(STAGE_SIGNATURE, "package contents do not match the sender's signature")
    passed(STAGE_SIGNATURE, f"VALID (RSA-PSS/SHA-256, key fp {public_key_fingerprint(sender_public)})")

    # 5. session key
    if pkg.header.get("receiver_key_fingerprint") != public_key_fingerprint(receiver_key):
        return failed(STAGE_KEY, "package was encrypted for a different receiver key")
    try:
        session_key = cu.rsa_oaep_unwrap(pkg.wrapped_key, receiver_key)
    except ValueError:
        return failed(STAGE_KEY, "RSA-OAEP unwrap failed (wrong private key or corrupted wrapped key)")
    passed(STAGE_KEY, f"AES-128 session key recovered, fp {key_fingerprint(session_key)}")

    # 6. decryption
    try:
        manifest = json.loads(cu.aes_cbc_decrypt(pkg.manifest_ciphertext, session_key, pkg.manifest_iv))
        data = cu.aes_cbc_decrypt(pkg.payload_ciphertext, session_key, pkg.payload_iv)
    except (ValueError, UnicodeDecodeError) as exc:
        return failed(STAGE_DECRYPT, f"decryption failed: {exc}")
    passed(STAGE_DECRYPT, f"{len(data)} bytes recovered")

    # 7. integrity
    recovered_hash = sha256_bytes(data)
    if not digests_match(recovered_hash, str(manifest.get("sha256", ""))) or len(data) != manifest.get("size"):
        return failed(STAGE_INTEGRITY, f"recovered {recovered_hash[:16]}... != reference "
                                       f"{str(manifest.get('sha256'))[:16]}...")
    passed(STAGE_INTEGRITY, f"VERIFIED {recovered_hash}")

    out.accepted, out.recovered, out.manifest = True, data, manifest
    return out
