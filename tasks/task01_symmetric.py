"""Task 1 - Symmetric encryption: AES-128-CBC and 3-DES-CBC.

The selected file is treated as raw bytes, so text, PDF, image and any other
binary file are handled identically.  For each cipher we:

1. generate a fresh random key and a fresh random IV,
2. encrypt (PKCS#7 padding, CBC mode) and save ``IV || ciphertext``,
3. read the saved container back, split off the IV and decrypt,
4. save the decrypted file and verify it is byte-for-byte identical.

Key/IV handling: keys exist only in memory for this run and are shown only as
fingerprints.  IVs are public values stored in clear at the start of each
``.enc`` file (16 bytes for AES, 8 bytes for 3-DES).
"""

from __future__ import annotations

import time
from pathlib import Path

from core import crypto_utils as cu
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import sha256_bytes
from core.key_manager import generate_3des_key, generate_aes_key, key_fingerprint
from core.logging_utils import get_logger
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main, resolve_input

TASK_ID = "task01"
TITLE = "Task 1 - Symmetric Encryption (AES-128-CBC & 3-DES-CBC)"

_log = get_logger(__name__)

# name -> (key generator, encrypt, decrypt, block size, file tag)
CIPHERS = {
    "AES-128-CBC": (generate_aes_key, cu.aes_cbc_encrypt, cu.aes_cbc_decrypt, cu.AES_BLOCK, "aes128cbc"),
    "3-DES-CBC": (generate_3des_key, cu.tdes_cbc_encrypt, cu.tdes_cbc_decrypt, cu.TDES_BLOCK, "3descbc"),
}


def encrypt_decrypt_roundtrip(name: str, plaintext: bytes, out_dir: Path, file_name: str) -> dict:
    """Encrypt, persist, reload, decrypt and verify one cipher. Returns metrics."""
    keygen, encrypt, decrypt, block, tag = CIPHERS[name]
    key = keygen()
    # Untimed warm-up so one-time library initialisation is not counted.
    warm_iv, warm_ct = encrypt(b"warm-up", key)
    decrypt(warm_ct, key, warm_iv)

    t0 = time.perf_counter()
    iv, ciphertext = encrypt(plaintext, key)
    t_enc = time.perf_counter() - t0
    enc_path = write_file_bytes(out_dir / f"{file_name}.{tag}.enc", cu.pack_iv_ciphertext(iv, ciphertext))

    # Receiver side: work only from what was written to disk.
    iv_rx, ct_rx = cu.unpack_iv_ciphertext(enc_path.read_bytes(), block)
    t0 = time.perf_counter()
    recovered = decrypt(ct_rx, key, iv_rx)
    t_dec = time.perf_counter() - t0
    dec_path = write_file_bytes(out_dir / f"decrypted_{tag}_{file_name}", recovered)

    match = recovered == plaintext
    _log.info("%s: %d -> %d bytes, round trip %s", name, len(plaintext), len(ciphertext),
              "OK" if match else "MISMATCH")
    return {
        "cipher": name,
        "key_bits": len(key) * 8,
        "key_fingerprint": key_fingerprint(key),
        "iv_hex": iv.hex(),
        "block_bytes": block,
        "plaintext_bytes": len(plaintext),
        "ciphertext_bytes": len(ciphertext),
        "padding_bytes": len(ciphertext) - len(plaintext),
        "encrypt_ms": round(t_enc * 1000, 3),
        "decrypt_ms": round(t_dec * 1000, 3),
        "sha256_decrypted": sha256_bytes(recovered),
        "match": match,
        "encrypted_file": enc_path,
        "decrypted_file": dec_path,
    }


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None) -> TaskResult:
    info = describe_file(resolve_input(input_path))
    plaintext = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)

    result = TaskResult(TASK_ID, TITLE)
    result.add("Input file", f"{info.name} ({info.type_label}, {info.human_size})")
    result.add("SHA-256 original", sha256_bytes(plaintext))

    runs = [encrypt_decrypt_roundtrip(n, plaintext, out_dir, info.name) for n in CIPHERS]
    for r in runs:
        label = r["cipher"]
        result.add(f"{label} key", f"{r['key_bits']}-bit random, fingerprint {r['key_fingerprint']}")
        result.add(f"{label} IV", r["iv_hex"])
        result.add(f"{label} encryption", f"PASS ({r['plaintext_bytes']} -> {r['ciphertext_bytes']} bytes, "
                                          f"{r['padding_bytes']} padding, single run {r['encrypt_ms']} ms)")
        result.add(f"{label} decryption", f"{'PASS' if r['match'] else 'FAIL'} (single run {r['decrypt_ms']} ms)")
        result.add(f"{label} bytes identical", "TRUE" if r["match"] else "FALSE")
        result.artifacts += [r["encrypted_file"], r["decrypted_file"]]

    all_ok = all(r["match"] for r in runs)
    result.status = Status.PASS if all_ok else Status.FAIL
    if not all_ok:
        result.reason = "Decrypted bytes differ from the original."
    result.data = {"file": info.name, "size_bytes": info.size_bytes,
                   "runs": [{k: v for k, v in r.items() if not k.endswith("_file")} for r in runs]}
    result.details = (
        "Both ciphers ran in CBC mode with PKCS#7 padding. Each .enc file is laid out as\n"
        "IV || ciphertext (IV = 16 bytes for AES, 8 bytes for 3-DES). The IV is random per\n"
        "encryption and not secret. The keys came from the OS CSPRNG, stayed in memory only,\n"
        "and appear here only as SHA-256 fingerprints.\n"
        "CBC gives confidentiality but not integrity. Detecting changes needs hashing,\n"
        "MACs or signatures (Tasks 8-10).\n"
        "Timings are single, indicative runs; Task 4 contains the controlled benchmark.\n"
        "3-DES is included for comparison only. It is deprecated (NIST SP 800-131A) because\n"
        "of its 64-bit block size and low speed."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
