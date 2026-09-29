"""Task 6 - Diffie-Hellman key exchange (honest parties, no attacker).

Sender and Receiver agree on a shared AES key over a public channel without
ever transmitting the key:

    public:   p (2048-bit safe prime), g = 2          [RFC 3526 group 14]
    Sender:   a random, A = g^a mod p   --A-->
    Receiver: b random, B = g^b mod p   <--B--
    Sender:   S = B^a mod p     Receiver: S = A^b mod p     (both = g^(ab))
    both:     K = HKDF-SHA256(S) -> AES-128 session key

Only public values are displayed or saved.  Private exponents are shown as
"<hidden>" (bit length only) and the shared secret/key only as fingerprints.
The derived key is then used for a real AES-128-CBC message round trip.

This task does not use a selected file: DH is a key-agreement protocol.
"""

from __future__ import annotations

import json
from pathlib import Path

from core import crypto_utils as cu
from core import diffie_hellman as dh
from core.file_handler import task_output_dir
from core.key_manager import key_fingerprint
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main

TASK_ID = "task06"
TITLE = "Task 6 - Diffie-Hellman Key Exchange"
DEMO_MESSAGE = b"Receiver: the student records transfer will start at 10:00. - Sender"


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None) -> TaskResult:
    """``input_path`` is accepted for a uniform interface but not needed."""
    out_dir = task_output_dir(TASK_ID, output_root)

    sender, receiver = dh.DHParty("Sender"), dh.DHParty("Receiver")

    # Public exchange: these values are all an eavesdropper ever sees.
    a_pub, b_pub = sender.public, receiver.public
    transcript = [
        {"step": 1, "from": "both", "to": "both", "field": "p", "value_hex": format(dh.P, "x")},
        {"step": 1, "from": "both", "to": "both", "field": "g", "value_hex": format(dh.G, "x")},
        {"step": 2, "from": "Sender", "to": "Receiver", "field": "A = g^a mod p", "value_hex": format(a_pub, "x")},
        {"step": 3, "from": "Receiver", "to": "Sender", "field": "B = g^b mod p", "value_hex": format(b_pub, "x")},
    ]

    # Each side computes the secret from its own private value + the peer's public value.
    s_sender, s_receiver = sender.shared_secret(b_pub), receiver.shared_secret(a_pub)
    k_sender, k_receiver = sender.session_key(b_pub), receiver.session_key(a_pub)
    secrets_match = s_sender == s_receiver
    keys_match = k_sender == k_receiver

    # Use the agreed key: Sender encrypts, Receiver decrypts.
    iv, ct = cu.aes_cbc_encrypt(DEMO_MESSAGE, k_sender)
    message_ok = cu.aes_cbc_decrypt(ct, k_receiver, iv) == DEMO_MESSAGE
    transcript.append({"step": 4, "from": "Sender", "to": "Receiver", "field": "AES-128-CBC message (IV||ct)",
                       "value_hex": (iv + ct).hex()})

    transcript_path = out_dir / "public_transcript.json"
    transcript_path.write_text(json.dumps({
        "group": dh.GROUP_NAME,
        "note": "Only values sent over the public channel. No private exponents or shared secrets.",
        "messages": transcript,
    }, indent=2), encoding="utf-8")

    passed = secrets_match and keys_match and message_ok
    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if passed else Status.FAIL, artifacts=[transcript_path])
    if not passed:
        result.reason = "Derived secrets differ."
    result.add("Group", f"{dh.GROUP_NAME}, g = {dh.G}")
    result.add("Prime p", dh.short_hex(dh.P))
    result.add("Sender private a", f"<hidden> ({sender.private_bits}-bit random exponent, OS CSPRNG)")
    result.add("Sender public A", dh.short_hex(a_pub))
    result.add("Receiver private b", f"<hidden> ({receiver.private_bits}-bit random exponent, OS CSPRNG)")
    result.add("Receiver public B", dh.short_hex(b_pub))
    result.add("Exchanged over channel", "p, g, A (Sender->Receiver), B (Receiver->Sender)")
    result.add("Sender computes", f"S = B^a mod p -> fingerprint {dh.secret_fingerprint(s_sender)}")
    result.add("Receiver computes", f"S = A^b mod p -> fingerprint {dh.secret_fingerprint(s_receiver)}")
    result.add("Shared secrets match", "TRUE" if secrets_match else "FALSE")
    result.add("Derived AES-128 key", f"HKDF-SHA256(S): Sender fp {key_fingerprint(k_sender)}, "
                                      f"Receiver fp {key_fingerprint(k_receiver)}")
    result.add("Encrypted message test", f"{'PASS' if message_ok else 'FAIL'} - Receiver decrypted Sender's "
                                         f"{len(DEMO_MESSAGE)}-byte message with its own derived key")
    result.data = {
        "group": dh.GROUP_NAME, "p_bits": dh.P.bit_length(),
        "sender_public_bits": a_pub.bit_length(), "receiver_public_bits": b_pub.bit_length(),
        "secrets_match": secrets_match, "keys_match": keys_match, "message_roundtrip": message_ok,
        "shared_secret_fingerprint": dh.secret_fingerprint(s_sender),
    }
    result.details = (
        "Both parties reached the same secret S = g^(ab) mod p without sending it. An\n"
        "eavesdropper who records the transcript learns p, g, A and B. Computing S from these\n"
        "requires solving the discrete-logarithm problem, which is infeasible for a 2048-bit\n"
        "group. S is never used directly as a key: HKDF-SHA256 turns it into a uniform\n"
        "128-bit AES key.\n"
        "Received public values are checked (1 < Y < p-1 and Y^q mod p = 1) to reject\n"
        "degenerate or small-subgroup inputs.\n"
        "Important: plain DH does not authenticate the parties. Neither side can tell whether\n"
        "A or B really came from the other; Task 7 exploits this with a man-in-the-middle."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0], takes_file=False)
