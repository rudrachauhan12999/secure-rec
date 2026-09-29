"""Task 8 - SHA-256 integrity verification.

1. Hash the original selected file (SHA-256, streamed from disk).
2. Obtain the "received" file: by default the file is encrypted with
   AES-128-CBC, written out, read back and decrypted into a separate
   recovered file (a simulated transfer); alternatively any existing file can
   be supplied as ``received_path`` (e.g. Task 5's recovered output).
3. Hash the received file.
4. Compare both digests (constant-time) and report INTEGRITY VERIFIED or not.

SHA-256 maps any input to a 256-bit digest; changing even one bit gives an
unrelated digest, so equal digests mean (with overwhelming probability)
identical bytes.  A bare hash proves integrity only against accidental or
third-party change if the reference hash itself is trustworthy - an attacker
who can modify the file can also recompute its hash.  Binding the hash to
the sender needs a MAC or a digital signature (Task 10).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core import crypto_utils as cu
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import digests_match, sha256_file
from core.key_manager import generate_aes_key
from core.results import Status, TaskResult, guarded
from tasks.common import resolve_input

TASK_ID = "task08"
TITLE = "Task 8 - SHA-256 Integrity Verification"


def simulated_transfer(src: Path, out_dir: Path) -> Path:
    """Encrypt -> store -> reload -> decrypt; returns the recovered file path."""
    key = generate_aes_key(128)
    iv, ct = cu.aes_cbc_encrypt(read_file_bytes(src), key)
    enc = write_file_bytes(out_dir / f"{src.name}.aes128cbc.enc", cu.pack_iv_ciphertext(iv, ct))
    iv_rx, ct_rx = cu.unpack_iv_ciphertext(enc.read_bytes(), cu.AES_BLOCK)
    return write_file_bytes(out_dir / f"recovered_{src.name}", cu.aes_cbc_decrypt(ct_rx, key, iv_rx))


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        received_path: str | Path | None = None) -> TaskResult:
    original = describe_file(resolve_input(input_path))
    out_dir = task_output_dir(TASK_ID, output_root)

    if received_path is None:
        received = describe_file(simulated_transfer(original.path, out_dir))
        source = "AES-128-CBC encrypt -> store -> decrypt (simulated transfer)"
    else:
        received = describe_file(received_path)
        source = "file supplied by user"

    h_orig, h_recv = sha256_file(original.path), sha256_file(received.path)
    match = digests_match(h_orig, h_recv)

    sums = out_dir / "sha256sums.txt"  # standard `sha256sum -c` format
    sums.write_text(f"{h_orig}  {original.name}\n{h_recv}  {received.name}\n", encoding="utf-8")

    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if match else Status.FAIL, artifacts=[sums])
    if received_path is None:
        result.artifacts[:0] = [out_dir / f"{original.name}.aes128cbc.enc", received.path]
    if not match:
        result.reason = "SHA-256 digests differ - the received file is not identical to the original."
    result.add("Original file", f"{original.name} ({original.type_label}, {original.size_bytes} bytes)")
    result.add("Received file", f"{received.name} ({received.size_bytes} bytes) - {source}")
    result.add("SHA-256 original", h_orig)
    result.add("SHA-256 received", h_recv)
    result.add("MATCH", "TRUE" if match else "FALSE")
    result.add("Integrity", "VERIFIED" if match else "NOT VERIFIED - file differs from original")
    result.data = {"original": original.name, "received": received.name, "sha256_original": h_orig,
                   "sha256_received": h_recv, "match": match, "size_original": original.size_bytes,
                   "size_received": received.size_bytes}
    result.details = (
        "Each digest is 256 bits (64 hex characters) and was computed by streaming the file\n"
        "from disk. Equal digests mean the received bytes are identical to the original.\n"
        "Limitation: a hash protects integrity only if the reference hash can be trusted.\n"
        "An attacker who can change the file can also recompute the hash. A signature\n"
        "(Task 10) binds the hash to the sender's private key, adding authentication."
    )
    result.save(out_dir)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", nargs="?", help="original file (default: data/student_records.txt)")
    parser.add_argument("--received", help="compare against this file instead of a simulated transfer")
    parser.add_argument("--out", help="output root directory (default: outputs/)")
    args = parser.parse_args()
    result = run(args.file, Path(args.out) if args.out else None, received_path=args.received)
    print(result.to_text())
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
