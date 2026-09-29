"""Task 9 - Tampering detection with SHA-256.

Scenario: the Sender publishes the SHA-256 of the original file as a trusted
reference (in practice protected by a signature - Task 10), encrypts the file
with AES-128-CBC and transmits ``IV || ciphertext``.  Four deliveries are
compared against the reference hash:

  A. untampered transfer                      -> MATCH TRUE,  INTEGRITY VERIFIED
  B1. one IV byte flipped in transit          -> MATCH FALSE, TAMPERING DETECTED
      (targeted CBC bit-flip: decryption succeeds WITHOUT any error and
       exactly one plaintext byte changes - encryption alone does not notice)
  B2. one ciphertext byte flipped in transit  -> MATCH FALSE, TAMPERING DETECTED
      (one block becomes garbage, one byte of the next block flips; if the
       padding breaks, decryption itself fails - also reported as detected)
  C. received file modified at rest           -> MATCH FALSE, TAMPERING DETECTED

Tamper positions are deterministic (derived from the file size) and logged,
so the experiment is reproducible.  Modified data is saved exactly as
received and is never repaired.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from core import crypto_utils as cu
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import digests_match, sha256_bytes
from core.key_manager import generate_aes_key
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main, resolve_input

TASK_ID = "task09"
TITLE = "Task 9 - Tampering Detection"


@dataclass
class Case:
    case_id: str
    description: str
    received_hash: str | None       # None if decryption itself failed
    decrypt_error: str = ""
    tamper_offset: int | None = None
    old_byte: int | None = None
    new_byte: int | None = None
    where: str = ""
    evidence: Path | None = None


def tamper(data: bytes, offset: int, xor_mask: int) -> tuple[bytes, int, int]:
    """Return a modified copy plus the old/new byte values at ``offset``."""
    if not 0 <= offset < len(data):
        raise IndexError("tamper offset outside data")
    buf = bytearray(data)
    old = buf[offset]
    buf[offset] ^= xor_mask
    return bytes(buf), old, buf[offset]


def receive(blob: bytes, key: bytes) -> tuple[bytes | None, str]:
    """Receiver side: decrypt whatever arrived; return (plaintext, error)."""
    try:
        iv, ct = cu.unpack_iv_ciphertext(blob, cu.AES_BLOCK)
        return cu.aes_cbc_decrypt(ct, key, iv), ""
    except ValueError as exc:
        return None, str(exc)


def verdict(reference: str, case: Case) -> tuple[bool, str]:
    """(match, text). A failed decryption is treated as detected tampering."""
    if case.received_hash is None:
        return False, f"TAMPERING DETECTED (decryption failed: {case.decrypt_error})"
    match = digests_match(reference, case.received_hash)
    return match, "INTEGRITY VERIFIED" if match else "TAMPERING DETECTED"


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None) -> TaskResult:
    info = describe_file(resolve_input(input_path))
    original = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)
    name = info.name

    # Sender: trusted reference hash + encrypted transmission.
    reference = sha256_bytes(original)
    key = generate_aes_key(128)
    iv, ct = cu.aes_cbc_encrypt(original, key)
    sent = cu.pack_iv_ciphertext(iv, ct)
    write_file_bytes(out_dir / f"transmitted_{name}.enc", sent)

    cases: list[Case] = []

    # A. untampered
    pt, err = receive(sent, key)
    cases.append(Case("A", "Untampered transfer", sha256_bytes(pt) if pt is not None else None, err,
                      evidence=write_file_bytes(out_dir / f"A_recovered_{name}", pt) if pt is not None else None))

    # B1. flip the lowest bit of IV byte 0 -> flips bit of plaintext byte 0 after decryption.
    blob, old, new = tamper(sent, 0, 0x01)
    write_file_bytes(out_dir / f"B1_tampered_iv_{name}.enc", blob)
    pt, err = receive(blob, key)
    cases.append(Case("B1", "IV byte modified in transit (targeted CBC bit-flip)",
                      sha256_bytes(pt) if pt is not None else None, err, 0, old, new, "IV",
                      write_file_bytes(out_dir / f"B1_received_{name}", pt) if pt is not None else None))

    # B2. corrupt the first byte of the middle ciphertext block.
    n_blocks = len(ct) // cu.AES_BLOCK
    offset = cu.AES_BLOCK + (n_blocks // 2) * cu.AES_BLOCK
    blob, old, new = tamper(sent, offset, 0xFF)
    write_file_bytes(out_dir / f"B2_tampered_ciphertext_{name}.enc", blob)
    pt, err = receive(blob, key)
    cases.append(Case("B2", f"Ciphertext byte modified in transit (block {n_blocks // 2} of {n_blocks})",
                      sha256_bytes(pt) if pt is not None else None, err, offset, old, new, "ciphertext",
                      write_file_bytes(out_dir / f"B2_received_{name}", pt) if pt is not None else None))

    # C. modify the correctly received file at rest (middle byte).
    at_rest, old, new = tamper(original, len(original) // 2, 0x01)
    cases.append(Case("C", "Received file modified at rest (1 bit of middle byte)", sha256_bytes(at_rest), "",
                      len(original) // 2, old, new, "plaintext file",
                      write_file_bytes(out_dir / f"C_modified_{name}", at_rest)))

    # Evidence: hashes + tamper log.
    sums = out_dir / "sha256sums.txt"
    with open(sums, "w", encoding="utf-8") as fh:
        fh.write(f"{reference}  {name}  (sender reference)\n")
        for c in cases:
            fh.write(f"{c.received_hash or '-' * 64}  case {c.case_id}"
                     f"{'  (' + c.evidence.name + ')' if c.evidence else '  (decryption failed)'}\n")
    log = out_dir / "tamper_log.csv"
    with open(log, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case", "description", "location", "offset", "old_byte", "new_byte",
                    "received_sha256", "match", "verdict"])
        for c in cases:
            match, text = verdict(reference, c)
            w.writerow([c.case_id, c.description, c.where, c.tamper_offset,
                        "" if c.old_byte is None else f"0x{c.old_byte:02x}",
                        "" if c.new_byte is None else f"0x{c.new_byte:02x}",
                        c.received_hash or "", match, text])

    result = TaskResult(TASK_ID, TITLE)
    result.add("Input file", f"{name} ({info.type_label}, {info.size_bytes} bytes)")
    result.add("Original hash (reference)", reference)
    outcomes = {}
    for c in cases:
        match, text = verdict(reference, c)
        outcomes[c.case_id] = {"match": match, "verdict": text, "received_sha256": c.received_hash,
                               "decrypt_error": c.decrypt_error, "offset": c.tamper_offset}
        result.add(f"[{c.case_id}] case", c.description)
        if c.tamper_offset is not None:
            result.add(f"[{c.case_id}]   modification", f"{c.where} offset {c.tamper_offset}: "
                                                         f"0x{c.old_byte:02x} -> 0x{c.new_byte:02x}")
        if c.case_id == "B1" and c.received_hash is not None:
            changed = sum(a != b for a, b in zip(original, read_file_bytes(c.evidence)))
            result.add(f"[{c.case_id}]   decryption", f"succeeded silently, {changed} plaintext byte(s) changed")
            outcomes[c.case_id]["plaintext_bytes_changed"] = changed
        result.add(f"[{c.case_id}]   received hash", c.received_hash or "(no output - decryption failed)")
        result.add(f"[{c.case_id}]   MATCH", "TRUE" if match else "FALSE")
        result.add(f"[{c.case_id}]   result", text)

    detected_all = all(not outcomes[k]["match"] for k in ("B1", "B2", "C"))
    genuine_ok = outcomes["A"]["match"]
    result.status = Status.PASS if genuine_ok and detected_all else Status.FAIL
    if result.status is Status.FAIL:
        result.reason = "Genuine file not verified or tampering missed."
    result.add("Summary", f"genuine transfer verified: {genuine_ok}; tampering detected in "
                          f"{sum(not outcomes[k]['match'] for k in ('B1', 'B2', 'C'))}/3 tampered cases")
    result.artifacts += [out_dir / f"transmitted_{name}.enc", out_dir / f"B1_tampered_iv_{name}.enc",
                         out_dir / f"B2_tampered_ciphertext_{name}.enc",
                         *[c.evidence for c in cases if c.evidence], sums, log]
    result.data = {"reference_sha256": reference, "cases": outcomes,
                   "genuine_verified": genuine_ok, "all_tampering_detected": detected_all}
    result.details = (
        "Tampered data was kept exactly as received; nothing was repaired.\n"
        "Case B1 shows why encryption is not integrity. Flipping one IV bit flips the same\n"
        "plaintext bit, and CBC decryption reports no error. Only the hash comparison\n"
        "exposes the change.\n"
        "Limitation: the hash must itself be trustworthy. An attacker who can replace both\n"
        "the file and its published hash defeats this check. Signing the hash (Task 10) or\n"
        "using an authenticated mode such as AES-GCM or HMAC closes that gap."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
