"""Task 5 - RSA + AES hybrid encryption.

1. Receiver generates an RSA-2048 key pair and publishes the public key.
2. Sender generates a random AES-128 session key.
3. Sender encrypts the file with AES-128-CBC (fast, any size).
4. Sender wraps the session key with RSA-OAEP (SHA-256) under the receiver's
   public key.  RSA never encrypts the file itself: RSA-2048/OAEP can carry
   at most 190 bytes and is orders of magnitude slower than AES.
5. The package (wrapped key + IV + ciphertext) is "sent": written into a
   simulated channel directory.
6. Receiver reads the package, unwraps the session key with its private key,
7. decrypts the file, and
8. the recovered bytes are compared with the original.

The receiver's private key exists only in memory; only the public key is
saved.  The session key is never written anywhere.
"""

from __future__ import annotations

import time
from pathlib import Path

from Crypto.PublicKey import RSA

from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import sha256_bytes
from core.hybrid import HybridPackage, hybrid_encrypt, unwrap_session_key
from core import crypto_utils as cu
from core.key_manager import (RSA_KEY_BITS, export_public_key_pem, generate_rsa_keypair,
                              key_fingerprint, public_key_fingerprint)
from core.logging_utils import get_logger
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main, resolve_input

TASK_ID = "task05"
TITLE = "Task 5 - RSA + AES Hybrid Encryption"

_log = get_logger(__name__)


def sender_side(plaintext: bytes, receiver_public_pem: bytes, channel_dir: Path, file_name: str) -> dict:
    """Everything the sender does. It only ever sees the receiver's PUBLIC key."""
    public_key = RSA.import_key(receiver_public_pem)
    package, session_key = hybrid_encrypt(plaintext, public_key)
    pkg_path = write_file_bytes(channel_dir / f"{file_name}.hybrid", package.to_bytes())
    _log.info("Sender: sent %d-byte package (wrapped key %d bytes)", pkg_path.stat().st_size,
              len(package.wrapped_key))
    return {"package_path": pkg_path, "package": package, "session_key_fp": key_fingerprint(session_key)}


def receiver_side(pkg_path: Path, private_key: RSA.RsaKey) -> tuple[bytes, str]:
    """Everything the receiver does, working only from the received bytes."""
    package = HybridPackage.from_bytes(pkg_path.read_bytes())
    session_key = unwrap_session_key(package, private_key)
    plaintext = cu.aes_cbc_decrypt(package.ciphertext, session_key, package.iv)
    return plaintext, key_fingerprint(session_key)


def wrong_key_is_rejected(package: HybridPackage) -> bool:
    """A different RSA private key must not be able to unwrap the session key."""
    try:
        cu.rsa_oaep_unwrap(package.wrapped_key, generate_rsa_keypair())
        return False
    except ValueError:
        return True


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        receiver_key: RSA.RsaKey | None = None, check_wrong_key: bool = True) -> TaskResult:
    """``receiver_key`` may be injected (tests); by default a fresh pair is generated."""
    info = describe_file(resolve_input(input_path))
    original = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)
    channel = out_dir / "transfer"

    # 1. Receiver key pair; only the public half is exported and saved.
    injected = receiver_key is not None
    t0 = time.perf_counter()
    receiver_key = receiver_key or generate_rsa_keypair(RSA_KEY_BITS)
    t_keygen = time.perf_counter() - t0
    public_pem = export_public_key_pem(receiver_key)
    pub_path = write_file_bytes(out_dir / "receiver_public_key.pem", public_pem)

    # 2-5. Sender.
    t0 = time.perf_counter()
    sent = sender_side(original, public_pem, channel, info.name)
    t_send = time.perf_counter() - t0
    package: HybridPackage = sent["package"]
    wk_path = write_file_bytes(out_dir / "wrapped_session_key.bin", package.wrapped_key)

    # 6-7. Receiver.
    t0 = time.perf_counter()
    recovered, rx_key_fp = receiver_side(sent["package_path"], receiver_key)
    t_recv = time.perf_counter() - t0
    rec_path = write_file_bytes(out_dir / f"recovered_{info.name}", recovered)

    # 8. Verification.
    key_ok = rx_key_fp == sent["session_key_fp"]
    match = recovered == original
    wrong_rejected = wrong_key_is_rejected(package) if check_wrong_key else None
    passed = key_ok and match and wrong_rejected is not False

    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if passed else Status.FAIL)
    if not passed:
        result.reason = "Hybrid round trip did not verify."
    result.add("Input file", f"{info.name} ({info.type_label}, {info.human_size})")
    result.add("RSA key pair", f"{receiver_key.size_in_bits()}-bit, public fp {public_key_fingerprint(receiver_key)} "
                               f"({'supplied by caller' if injected else f'generated in {t_keygen:.2f} s'})")
    result.add("Receiver private key", "kept in memory only - not saved or displayed")
    result.add("AES session key", f"AES-128 random, fingerprint {sent['session_key_fp']} (never stored)")
    result.add("File encryption", f"PASS AES-128-CBC, {len(original)} -> {len(package.ciphertext)} bytes")
    result.add("Session key wrapping", f"PASS RSA-OAEP-SHA256, 16 -> {len(package.wrapped_key)} bytes")
    result.add("Simulated transfer", f"{sent['package_path'].name}, {sent['package_path'].stat().st_size} bytes "
                                     f"(sender {t_send * 1000:.1f} ms)")
    result.add("Receiver key recovery", f"{'PASS' if key_ok else 'FAIL'} (unwrapped key fp {rx_key_fp})")
    result.add("Receiver decryption", f"{'PASS' if match else 'FAIL'} ({t_recv * 1000:.1f} ms)")
    if wrong_rejected is not None:
        result.add("Wrong RSA key rejected", "PASS" if wrong_rejected else "FAIL")
    result.add("SHA-256 original", sha256_bytes(original))
    result.add("SHA-256 recovered", sha256_bytes(recovered))
    result.add("Original bytes == recovered bytes", "TRUE" if match else "FALSE")
    result.artifacts += [pub_path, sent["package_path"], wk_path, rec_path]
    result.data = {
        "file": info.name, "size_bytes": len(original), "rsa_bits": receiver_key.size_in_bits(),
        "wrapped_key_bytes": len(package.wrapped_key), "package_bytes": sent["package_path"].stat().st_size,
        "session_key_recovered": key_ok, "match": match, "wrong_key_rejected": wrong_rejected,
    }
    result.details = (
        "Package layout: 'SRECHYB1' | wrapped-key length (2 bytes) | RSA-OAEP(session key) | IV | AES ciphertext.\n"
        "Hybrid encryption uses each algorithm for what it does well. AES encrypts the bulk\n"
        "data quickly. RSA solves key distribution, because the sender needs only the\n"
        "receiver's public key. The private key never left the receiver (memory only).\n"
        "Limitations: this gives confidentiality only. Nothing yet proves who sent the\n"
        "package or that it was not replaced in transit; that needs signatures and\n"
        "certificates (Tasks 10-11). CBC ciphertext can also be altered undetected without\n"
        "a hash, MAC or signature (Tasks 8-9)."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
