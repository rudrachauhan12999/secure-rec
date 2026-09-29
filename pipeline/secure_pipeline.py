"""Integrated end-to-end secure file transfer (Sender -> Receiver).

    python -m pipeline.secure_pipeline [file]                 normal transfer
    python -m pipeline.secure_pipeline [file] --tamper        tamper demo (ciphertext)
    python -m pipeline.secure_pipeline [file] --tamper certificate|signature|wrapped-key|impersonation

Setup (out of band, before any transfer)
  * Receiver generates an RSA-2048 key pair and publishes the public key.
  * Sender generates an RSA-2048 signing key and a self-signed X.509
    certificate (OpenSSL).  The receiver PINS that certificate's SHA-256
    fingerprint in its trust store.  This is an educational stand-in for a
    CA: a self-signed certificate provides NO real-world CA trust.

Sender
  1. read file bytes; record name, type, size, SHA-256
  2. fresh random AES-128 session key
  3. AES-128-CBC encrypt the file (random IV) and the metadata manifest
  4. wrap the session key with RSA-OAEP-SHA256 (receiver public key)
  5. sign the package structure with RSA-PSS-SHA256 (see pipeline/package.py)
  6. attach the certificate
Transfer
  7. only the serialized package is "sent" (written to sender/transfer_package.srpkg)
Receiver (pipeline/receiver.py) - stops at the first failed check
  8. certificate, pinned identity, signature, RSA unwrap, AES decrypt, SHA-256
  9. byte-for-byte comparison with the original (possible here because both
     sides run in one process for the demonstration)

Private keys are written only to keys/integrated_pipeline/ (git-ignored):
the sender key because OpenSSL needs it to self-sign, the receiver key so
the separate network demo (pipeline.network_demo) can decrypt.  The raw
session key is never written anywhere.
"""

from __future__ import annotations

import argparse
import json
import shutil
import ssl
import sys
from pathlib import Path

from Crypto.PublicKey import RSA

from core import certificates as certs
from core.config import KEYS_DIR
from core.crypto_utils import flip_bit
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import sha256_bytes
from core.key_manager import export_public_key_pem, generate_rsa_keypair, public_key_fingerprint
from core.results import Status, TaskResult, guarded
from core.signatures import sign_pss
from pipeline import receiver as rx
from pipeline.package import TransferPackage, certificate_fingerprint
from pipeline.sender import SENDER_SUBJECT, build_manifest, create_sender_identity, seal_package
from tasks.common import resolve_input

TASK_ID = "integrated_pipeline"
TITLE = "Integrated Secure File Transfer Pipeline"
PACKAGE_NAME = "transfer_package.srpkg"
STAGE_BYTES = "Byte-for-byte match"

# tamper target -> (description, receiver stage expected to catch it)
TAMPER_TARGETS = {
    "ciphertext": ("one byte of the encrypted file changed in transit", rx.STAGE_SIGNATURE),
    "wrapped-key": ("one byte of the RSA-wrapped session key changed", rx.STAGE_SIGNATURE),
    "signature": ("one bit of the digital signature changed", rx.STAGE_SIGNATURE),
    "certificate": ("one byte of the certificate's signature changed", rx.STAGE_CERT),
    "impersonation": ("attacker replaces the certificate with its OWN valid self-signed certificate "
                      "(same subject name) and re-signs the package with its own key", rx.STAGE_IDENTITY),
}


# ---------------------------------------------------------------- tampering
def tamper_package(target: str, package: TransferPackage, keys_dir: Path, tamper_dir: Path,
                   attacker_key: RSA.RsaKey | None = None) -> bytes:
    """Return modified package bytes. The genuine package object is not changed."""
    pkg = TransferPackage.from_bytes(package.to_bytes())   # independent copy
    if target == "ciphertext":
        pkg.payload_ciphertext = flip_bit(pkg.payload_ciphertext, (len(pkg.payload_ciphertext) // 2) * 8)
    elif target == "wrapped-key":
        pkg.wrapped_key = flip_bit(pkg.wrapped_key, 8 * 100)
    elif target == "signature":
        pkg.signature = flip_bit(pkg.signature, 8 * 10)
    elif target == "certificate":
        der = bytearray(ssl.PEM_cert_to_DER_cert(pkg.sender_certificate_pem))
        der[-5] ^= 0xFF                                      # inside the certificate's signature value
        pkg.sender_certificate_pem = ssl.DER_cert_to_PEM_cert(bytes(der))
    elif target == "impersonation":
        attacker = create_sender_identity(keys_dir / "attacker_demo", tamper_dir, attacker_key)
        attacker.certificate_path.replace(tamper_dir / "attacker_certificate.pem")
        pkg.sender_certificate_pem = attacker.certificate_pem
        pkg.signature = sign_pss(pkg.signed_bytes(), attacker.key)
    else:
        raise ValueError(f"unknown tamper target {target!r}; choose from {', '.join(TAMPER_TARGETS)}")
    return pkg.to_bytes()


# ---------------------------------------------------------------- reporting
def _line(label: str, value: str) -> str:
    return f"{label:<28}: {value}"


def _stage_value(outcome: rx.ReceiverOutcome, stage: str, ok_text: str, fail_text: str) -> str:
    result = outcome.stage(stage)
    if result is None:
        return "NOT RUN (stopped at earlier failure)"
    return ok_text if result.ok else f"{fail_text} - {result.detail}"


def format_report(info, original_sha: str, outcome: rx.ReceiverOutcome, byte_match: bool | None,
                  final: str, sender_facts: dict) -> str:
    wrapped = f"PASS (RSA-OAEP-SHA256, {sender_facts['wrapped_key_bytes']}-byte wrapped key)"
    lines = [
        "INPUT", "------",
        _line("Filename", info.name),
        _line("File type", info.type_label),
        _line("File size", f"{info.size_bytes} bytes ({info.human_size})"),
        _line("Original SHA-256", original_sha),
        "", "SECURITY", "--------",
        _line("AES encryption", f"PASS (AES-128-CBC, random IV, {sender_facts['ciphertext_bytes']} bytes)"),
        _line("RSA key protection", _stage_value(outcome, rx.STAGE_KEY, wrapped, "FAIL")),
        _line("Certificate verification", _stage_value(outcome, rx.STAGE_CERT, "PASS", "FAIL")),
        _line("Sender identity (pinned)", _stage_value(outcome, rx.STAGE_IDENTITY, "PASS", "FAIL")),
        _line("Digital signature", _stage_value(outcome, rx.STAGE_SIGNATURE, "VALID", "INVALID")),
        _line("SHA-256 integrity", _stage_value(outcome, rx.STAGE_INTEGRITY, "VERIFIED", "NOT VERIFIED")),
        "", "RECOVERY", "--------",
        _line("Recovered file", "PASS" if outcome.accepted else "NOT PRODUCED (package rejected)"),
        _line("Byte-for-byte match", "TRUE" if byte_match else ("FALSE" if byte_match is False else "N/A")),
        "", "FINAL RESULT", "------------", final,
    ]
    return "\n".join(lines)


EXPLANATION = """\
RECEIVER STAGES (in order; processing stops at the first failure)
{stages}

WHAT EACH MECHANISM PROVIDES
  Encryption (AES-128-CBC)      confidentiality of the file and its metadata
  RSA-OAEP key wrapping         only the intended receiver can recover the session key
  Hashing (SHA-256)             integrity: the recovered bytes equal the sender's original
  Digital signature (RSA-PSS)   authenticity + integrity of every transmitted field
  Certificate (X.509)           binds the signature key to the sender's name. It is
                                self-signed, so it is trusted only because its fingerprint
                                was pinned beforehand; it gives NO real-world CA trust

TRANSMITTED PACKAGE ({package_bytes} bytes): header, sender certificate, RSA-wrapped session
key, encrypted manifest (filename/type/size/SHA-256), encrypted file, signature. It contains
no plaintext, no raw session key and no private key. The exact signed structure is in
sender/signed_structure.json."""


# ------------------------------------------------------------------- run
@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None, keys_dir: Path | None = None,
        tamper: str | None = None, sender_key: RSA.RsaKey | None = None,
        receiver_key: RSA.RsaKey | None = None, attacker_key: RSA.RsaKey | None = None) -> TaskResult:
    """Run the whole transfer. Keys may be injected (tests); by default fresh RSA-2048 pairs are made."""
    if tamper is not None and tamper not in TAMPER_TARGETS:
        raise ValueError(f"unknown tamper target {tamper!r}; choose from {', '.join(TAMPER_TARGETS)}")
    certs.openssl_version()                                       # fail early with a clear message
    info = describe_file(resolve_input(input_path))
    data = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)
    sender_dir, receiver_dir, tamper_dir = out_dir / "sender", out_dir / "receiver", out_dir / "tamper"
    keys_dir = keys_dir or (KEYS_DIR / TASK_ID)
    for stale in (sender_dir, receiver_dir, tamper_dir):
        shutil.rmtree(stale, ignore_errors=True)                  # never mix results of an earlier run

    # ---- setup: receiver keys, sender identity, pinned trust ----
    receiver_key = receiver_key or generate_rsa_keypair()
    certs.write_private_key(receiver_key, keys_dir / "receiver_private_key.pem")
    write_file_bytes(receiver_dir / "receiver_public_key.pem", export_public_key_pem(receiver_key))
    identity = create_sender_identity(keys_dir, sender_dir, sender_key)
    trust = rx.TrustStore(SENDER_SUBJECT["CN"], certificate_fingerprint(identity.certificate_pem))
    trust.save(keys_dir / "trust_store.json")

    # ---- sender ----
    original_sha = sha256_bytes(data)
    package, session_fp = seal_package(data, build_manifest(info, data), identity, receiver_key.publickey())
    package_bytes = package.to_bytes()
    pkg_path = write_file_bytes(sender_dir / PACKAGE_NAME, package_bytes)
    signed_path = sender_dir / "signed_structure.json"
    signed_path.write_text(json.dumps(package.signed_structure(), indent=2), encoding="utf-8")

    # ---- transfer (optionally tampered in transit) ----
    transmitted = package_bytes
    artifacts = [pkg_path, signed_path, identity.certificate_path, receiver_dir / "receiver_public_key.pem"]
    if tamper:
        transmitted = tamper_package(tamper, package, keys_dir, tamper_dir, attacker_key)
        artifacts.append(write_file_bytes(tamper_dir / f"tampered_{PACKAGE_NAME}", transmitted))

    # ---- receiver ----
    outcome = rx.receive_package(transmitted, receiver_key, trust, receiver_dir)
    byte_match = None
    if outcome.accepted:
        byte_match = outcome.recovered == data
        artifacts.append(write_file_bytes(receiver_dir / f"recovered_{info.name}", outcome.recovered))
        outcome.stages.append(rx.StageResult(STAGE_BYTES, byte_match, "recovered bytes == original bytes"
                                             if byte_match else "recovered bytes differ from original"))
    artifacts.append(receiver_dir / "received_sender_certificate.pem")

    # ---- verdict ----
    if tamper:
        expected_stage = TAMPER_TARGETS[tamper][1]
        detected = not outcome.accepted and outcome.failed_stage == expected_stage
        final = (f"TAMPERING DETECTED - TRANSFER REJECTED at stage '{outcome.failed_stage}'"
                 if not outcome.accepted else "TAMPERING NOT DETECTED - FILE ACCEPTED")
        status = Status.PASS if detected else Status.FAIL
    else:
        success = outcome.accepted and bool(byte_match)
        final = "SECURE TRANSFER SUCCESSFUL" if success else f"SECURE TRANSFER FAILED at stage '{outcome.failed_stage}'"
        status = Status.PASS if success else Status.FAIL

    sender_facts = {"wrapped_key_bytes": len(package.wrapped_key), "ciphertext_bytes": len(package.payload_ciphertext)}
    result = TaskResult(TASK_ID, TITLE, status=status, artifacts=artifacts)
    if status is Status.FAIL:
        result.reason = final
    result.add("Mode", f"TAMPER DEMONSTRATION ({tamper}: {TAMPER_TARGETS[tamper][0]})" if tamper
               else "Normal transfer")
    result.add("Input", f"{info.name} ({info.type_label}, {info.human_size})")
    result.add("Session key", f"AES-128, fingerprint {session_fp} (raw key never stored)")
    result.add("Receiver key", f"RSA-{receiver_key.size_in_bits()}, public fp {public_key_fingerprint(receiver_key)}")
    result.add("Sender certificate", f"self-signed, SHA-256 {trust.certificate_sha256[:16]}... (pinned)")
    result.add("Package sent", f"{PACKAGE_NAME}, {len(package_bytes)} bytes")
    if outcome.failed_stage:
        result.add("Failed stage", f"{outcome.failed_stage} - {next(s.detail for s in outcome.stages if not s.ok)}")
    result.add("FINAL RESULT", final)

    stage_lines = "\n".join(f"  [{'PASS' if s.ok else 'FAIL'}] {s.stage}: {s.detail}" for s in outcome.stages)
    not_run = [s for s in rx.RECEIVER_STAGES if outcome.stage(s) is None]
    if not_run:
        stage_lines += "\n" + "\n".join(f"  [----] {s}: not run" for s in not_run)
    result.details = (format_report(info, original_sha, outcome, byte_match, final, sender_facts) + "\n\n"
                      + EXPLANATION.format(stages=stage_lines, package_bytes=len(package_bytes)))
    result.data = {
        "mode": tamper or "normal",
        "file": info.name, "size_bytes": info.size_bytes, "original_sha256": original_sha,
        "accepted": outcome.accepted, "failed_stage": outcome.failed_stage, "byte_match": byte_match,
        "stages": [{"stage": s.stage, "ok": s.ok, "detail": s.detail} for s in outcome.stages],
        "session_key_fingerprint": session_fp,
        "receiver_key_fingerprint": public_key_fingerprint(receiver_key),
        "sender_certificate_sha256": trust.certificate_sha256,
        "package_bytes": len(package_bytes), "package_path": str(pkg_path),
        "expected_detection_stage": TAMPER_TARGETS[tamper][1] if tamper else None,
        "final_result": final,
    }
    result.save(out_dir)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="SECURE-REC integrated secure file-transfer pipeline")
    parser.add_argument("file", nargs="?", help="file to transfer (default: data/student_records.txt)")
    parser.add_argument("--tamper", nargs="?", const="ciphertext", choices=list(TAMPER_TARGETS),
                        help="demonstrate detection of an in-transit modification (default target: ciphertext)")
    parser.add_argument("--out", help="output root directory (default: outputs/)")
    parser.add_argument("--keys", help="key directory (default: keys/integrated_pipeline/)")
    args = parser.parse_args()
    result = run(args.file, Path(args.out) if args.out else None, Path(args.keys) if args.keys else None,
                 tamper=args.tamper)
    print(result.to_text())
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
