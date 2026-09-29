"""Task 2 - Avalanche effect in AES.

A good block cipher makes every output bit depend on every input bit: a
single flipped plaintext bit should flip about 50 % of the ciphertext bits.

Controlled experiment (important)
---------------------------------
The original and the one-bit-modified plaintext are encrypted with the SAME
key and the SAME IV.  This is done deliberately and only for measurement: in
normal use every encryption gets a new random IV, and a different IV alone
already changes ~50 % of the ciphertext, which would hide the effect of the
single plaintext bit we want to observe.  Never reuse an IV in real use.

Measurements
------------
A. Whole file, AES-128-CBC: bits changed across the full ciphertext, plus a
   per-block breakdown.  In CBC a change in block i propagates to blocks i..n
   via chaining, while blocks before i stay identical.
B. Single block, raw AES: the 16-byte block containing the flipped bit is
   passed through the AES permutation alone (the "pure" avalanche).
C. Statistics: repeat B for every one of the 128 bit positions of that block.
"""

from __future__ import annotations

import csv
import statistics
from pathlib import Path

from Crypto.Util.Padding import pad

from core import crypto_utils as cu
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.key_manager import generate_aes_key, generate_iv, key_fingerprint
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main, resolve_input

TASK_ID = "task02"
TITLE = "Task 2 - Avalanche Effect (AES)"
BLOCK_BITS = cu.AES_BLOCK * 8


def pct(changed: int, total: int) -> float:
    return round(100.0 * changed / total, 2) if total else 0.0


def per_block_differences(c1: bytes, c2: bytes, block: int = cu.AES_BLOCK) -> list[int]:
    return [cu.count_differing_bits(c1[i:i + block], c2[i:i + block]) for i in range(0, len(c1), block)]


def single_block_avalanche(block: bytes, key: bytes, bit_in_block: int) -> int:
    """Changed output bits of one raw AES block when one input bit is flipped."""
    return cu.count_differing_bits(
        cu.aes_encrypt_single_block(block, key),
        cu.aes_encrypt_single_block(cu.flip_bit(block, bit_in_block), key),
    )


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        bit_index: int = 0) -> TaskResult:
    """``bit_index`` selects the plaintext bit to flip (0 = MSB of the first byte)."""
    info = describe_file(resolve_input(input_path))
    original = read_file_bytes(info.path)
    if not 0 <= bit_index < len(original) * 8:
        raise ValueError(f"bit_index {bit_index} is outside the {len(original) * 8}-bit input")
    modified = cu.flip_bit(original, bit_index)
    out_dir = task_output_dir(TASK_ID, output_root)

    # Controlled setup: one key and ONE fixed IV for both encryptions.
    key, iv = generate_aes_key(128), generate_iv(cu.AES_BLOCK)

    # --- A: whole-file AES-128-CBC ----------------------------------------
    _, c_orig = cu.aes_cbc_encrypt(original, key, iv=iv)
    _, c_mod = cu.aes_cbc_encrypt(modified, key, iv=iv)
    blocks = per_block_differences(c_orig, c_mod)
    changed_block = bit_index // BLOCK_BITS
    total_bits = len(c_orig) * 8
    changed_total = sum(blocks)
    affected_bits = (len(blocks) - changed_block) * BLOCK_BITS
    changed_affected = sum(blocks[changed_block:])

    # --- B: single raw AES block --------------------------------------------
    start = changed_block * cu.AES_BLOCK
    block_pt = pad(original, cu.AES_BLOCK)[start:start + cu.AES_BLOCK]
    bit_in_block = bit_index % BLOCK_BITS
    single = single_block_avalanche(block_pt, key, bit_in_block)

    # --- C: every bit position of that block ---------------------------------
    sweep = [single_block_avalanche(block_pt, key, b) for b in range(BLOCK_BITS)]
    sweep_pct = [pct(s, BLOCK_BITS) for s in sweep]

    # --- evidence files --------------------------------------------------------
    arts = [
        write_file_bytes(out_dir / f"modified_{info.name}", modified),
        write_file_bytes(out_dir / "ciphertext_original.bin", c_orig),
        write_file_bytes(out_dir / "ciphertext_modified.bin", c_mod),
    ]
    blocks_csv = out_dir / "per_block_bit_differences.csv"
    with open(blocks_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["block_index", "bits_changed", "bits_in_block", "percent_changed"])
        for i, n in enumerate(blocks):
            w.writerow([i, n, BLOCK_BITS, pct(n, BLOCK_BITS)])
    sweep_csv = out_dir / "single_block_bit_sweep.csv"
    with open(sweep_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["flipped_bit_in_block", "output_bits_changed", "percent_changed"])
        w.writerows(zip(range(BLOCK_BITS), sweep, sweep_pct))
    arts += [blocks_csv, sweep_csv]

    byte_pos, bit_pos = divmod(bit_index, 8)
    result = TaskResult(TASK_ID, TITLE, status=Status.COMPLETED, artifacts=arts)
    result.add("Input file", f"{info.name} ({info.human_size})")
    result.add("Bit flipped", f"bit {bit_index} (byte {byte_pos}, bit {bit_pos} from MSB) "
                              f"0x{original[byte_pos]:02x} -> 0x{modified[byte_pos]:02x}")
    result.add("Plaintext bits differing", cu.count_differing_bits(original, modified))
    result.add("Setup", f"AES-128, key fp {key_fingerprint(key)}, SAME fixed IV {iv.hex()} for both")
    result.add("A. CBC whole ciphertext",
               f"{changed_total}/{total_bits} bits changed = {pct(changed_total, total_bits)} %")
    result.add("A. CBC from changed block on",
               f"{changed_affected}/{affected_bits} bits = {pct(changed_affected, affected_bits)} % "
               f"(blocks {changed_block}..{len(blocks) - 1})")
    result.add("A. CBC blocks before change",
               f"{changed_block} block(s), {sum(blocks[:changed_block])} bits changed (expected 0)")
    result.add("B. Single AES block", f"{single}/{BLOCK_BITS} bits changed = {pct(single, BLOCK_BITS)} %")
    result.add("C. All 128 bit positions",
               f"mean {statistics.mean(sweep_pct):.2f} %, min {min(sweep_pct)} %, max {max(sweep_pct)} %")
    result.data = {
        "bit_index": bit_index,
        "ciphertext_bits": total_bits,
        "changed_bits_total": changed_total,
        "changed_percent_total": pct(changed_total, total_bits),
        "changed_block_index": changed_block,
        "changed_percent_from_changed_block": pct(changed_affected, affected_bits),
        "bits_changed_before_changed_block": sum(blocks[:changed_block]),
        "single_block_changed_bits": single,
        "single_block_changed_percent": pct(single, BLOCK_BITS),
        "sweep_mean_percent": round(statistics.mean(sweep_pct), 2),
        "sweep_min_percent": min(sweep_pct),
        "sweep_max_percent": max(sweep_pct),
    }
    result.details = (
        "This is a controlled experiment. Both plaintexts were encrypted with the same key\n"
        "and the same IV, so the only difference in the input is the one flipped bit.\n"
        "With a new random IV (normal, correct use) the two ciphertexts would differ by about\n"
        "50 % anyway, and that would hide the effect being measured.\n"
        "Expected results: about 50 % of the bits change in every affected block. In CBC the\n"
        "change carries forward through the chain to every later block. Blocks before the\n"
        "flipped bit do not change. Real systems must never reuse an IV."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
