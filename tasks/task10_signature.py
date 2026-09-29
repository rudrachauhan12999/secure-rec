"""Task 10 - Digital signature (RSA-PSS with SHA-256).

Sender:   h = SHA-256(file);  s = RSA-PSS-Sign(private key, h)
Receiver: accepts the file only if RSA-PSS-Verify(public key, SHA-256(file), s)

Checks performed:
  1. unchanged file + genuine public key      -> VALID
  2. modified file (one bit changed)          -> INVALID
  3. unchanged file + different public key    -> INVALID (not signed by that party)
  4. unchanged file + altered signature       -> INVALID

The receiver side works only from what is on disk: the file, the ``.sig``
file and the sender's public key PEM.  The private key stays in memory and is
never written; outputs contain only the public key, the signature, the
modified copy and the reports.

What provides what:
  confidentiality            - encryption (AES, RSA-OAEP): only key holders can read
  integrity                  - hashing (SHA-256): any change alters the digest
  authenticity / non-repudiation - digital signature: only the private-key holder
                               could have produced s, and anyone can verify it
"""

from __future__ import annotations

from pathlib import Path

from Crypto.PublicKey import RSA

from core.crypto_utils import flip_bit
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.hashing import sha256_bytes
from core.key_manager import export_public_key_pem, generate_rsa_keypair, public_key_fingerprint
from core.results import Status, TaskResult, guarded
from core.signatures import sign_pss, verify_pss
from tasks.common import cli_main, resolve_input

TASK_ID = "task10"
TITLE = "Task 10 - Digital Signature (RSA-PSS / SHA-256)"

PROPERTIES = (
    ("Confidentiality", "Encryption (AES-128-CBC, RSA-OAEP)", "Keeps content secret from outsiders"),
    ("Integrity", "Hashing (SHA-256)", "Detects any change to the data"),
    ("Authenticity / non-repudiation", "Digital signature (RSA-PSS)",
     "Proves which private key signed the data; the signer cannot credibly deny it"),
)


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        signing_key: RSA.RsaKey | None = None, impostor_key: RSA.RsaKey | None = None) -> TaskResult:
    """Keys may be injected (tests); by default fresh RSA-2048 pairs are generated."""
    info = describe_file(resolve_input(input_path))
    data = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)

    # --- Sender --------------------------------------------------------------
    signing_key = signing_key or generate_rsa_keypair()
    digest = sha256_bytes(data)
    signature = sign_pss(data, signing_key)                     # signs SHA-256(data)
    pub_path = write_file_bytes(out_dir / "sender_public_key.pem", export_public_key_pem(signing_key))
    sig_path = write_file_bytes(out_dir / f"{info.name}.sig", signature)
    (out_dir / f"{info.name}.sig.hex").write_text(signature.hex() + "\n", encoding="utf-8")

    # --- Receiver: only public material from disk -----------------------------
    sender_public = RSA.import_key(pub_path.read_bytes())
    received_sig = sig_path.read_bytes()

    modified = flip_bit(data, (len(data) // 2) * 8 + 7)       # lowest bit of the middle byte
    mod_path = write_file_bytes(out_dir / f"modified_{info.name}", modified)
    impostor_public = (impostor_key or generate_rsa_keypair()).publickey()
    bad_sig = flip_bit(received_sig, 8 * 10)

    checks = {
        "original_file_genuine_key": verify_pss(data, received_sig, sender_public),
        "modified_file": verify_pss(mod_path.read_bytes(), received_sig, sender_public),
        "impostor_public_key": verify_pss(data, received_sig, impostor_public),
        "altered_signature": verify_pss(data, bad_sig, sender_public),
    }
    expected = {"original_file_genuine_key": True, "modified_file": False,
                "impostor_public_key": False, "altered_signature": False}
    passed = checks == expected

    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if passed else Status.FAIL)
    if not passed:
        result.reason = "Signature checks did not behave as expected."
    v = lambda ok: "VALID" if ok else "INVALID"  # noqa: E731
    result.add("Input file", f"{info.name} ({info.type_label}, {info.size_bytes} bytes)")
    result.add("Sender key pair", f"RSA-{signing_key.size_in_bits()}, public fp "
                                  f"{public_key_fingerprint(signing_key)} (private key memory only)")
    result.add("SHA-256 of file", digest)
    result.add("Signature", f"RSA-PSS/SHA-256, {len(signature)} bytes, {signature[:12].hex()}...")
    result.add("1. Original file", f"{v(checks['original_file_genuine_key'])} - signature verified with "
                                   f"sender's public key")
    result.add("2. Modified file", f"{v(checks['modified_file'])} - 1 bit changed at byte {len(data) // 2}, "
                                   f"SHA-256 now {sha256_bytes(modified)[:16]}...")
    result.add("3. Wrong public key", f"{v(checks['impostor_public_key'])} - impostor key fp "
                                      f"{public_key_fingerprint(impostor_public)}")
    result.add("4. Altered signature", f"{v(checks['altered_signature'])} - 1 bit of the signature flipped")
    for prop, mechanism, meaning in PROPERTIES:
        result.add(prop, f"{mechanism}: {meaning}")
    result.artifacts += [pub_path, sig_path, out_dir / f"{info.name}.sig.hex", mod_path]
    result.data = {"file": info.name, "sha256": digest, "signature_bytes": len(signature),
                   "public_key_fingerprint": public_key_fingerprint(signing_key), "checks": checks}
    result.details = (
        "RSA-PSS uses randomised padding, so signing the same file twice gives different\n"
        "signatures, and both verify.\n"
        "Verification recomputes SHA-256 of the received file and checks it against the\n"
        "signature using the sender's public key. Changing one bit of the file or the\n"
        "signature makes verification fail, and so does using another party's key.\n"
        "Limitation: the check is only as good as the receiver's confidence that\n"
        "sender_public_key.pem really belongs to the sender. Binding the key to an\n"
        "identity is the role of certificates (Task 11)."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
