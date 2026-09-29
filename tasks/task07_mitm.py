"""Task 7 - Man-in-the-middle attack on unauthenticated Diffie-Hellman.

*** INTENTIONALLY SIMULATED ATTACK - educational only. ***
Everything happens in memory inside this process: the "network" is a
``SimulatedChannel`` object and the attacker is a hook on that object.  No
real traffic is intercepted, sent or modified.

Phase 1 - attack on plain DH (Sender <-> Attacker <-> Receiver)
    The attacker replaces A and B with its own public values, so
    Sender shares key K1 with the attacker (believing it is the Receiver) and
    Receiver shares key K2 with the attacker (believing it is the Sender).
    The attacker decrypts, reads, optionally alters and re-encrypts traffic;
    both victims see a perfectly working "secure" channel.

Phase 2 - mitigation: authenticated DH
    Each party signs its DH public value with a long-term RSA identity key
    (RSA-PSS/SHA-256); the peer verifies it with the *trusted* public key
    (pre-distributed or certified, see Task 11).  The attacker cannot produce
    a valid signature for its substituted value, so the handshake is aborted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from Crypto.PublicKey import RSA

from core import crypto_utils as cu
from core import diffie_hellman as dh
from core.file_handler import describe_file, read_file_bytes, task_output_dir
from core.hashing import sha256_bytes
from core.key_manager import generate_rsa_keypair, key_fingerprint, public_key_fingerprint
from core.results import Status, TaskResult, guarded
from core.signatures import sign_pss, verify_pss
from tasks.common import cli_main, resolve_input

TASK_ID = "task07"
TITLE = "Task 7 - Diffie-Hellman MITM Attack (SIMULATION)"

ORIGINAL_ORDER = b"Release final grades: student_id=42 G3=11"
TAMPERED_ORDER = b"Release final grades: student_id=42 G3=19"


# ------------------------------------------------------------ simulated network
@dataclass
class Message:
    src: str
    dst: str
    kind: str                 # "dh_public" | "ciphertext"
    payload: Any              # int for dh_public, (iv, ct) for ciphertext
    signature: bytes | None = None


def describe(msg: Message) -> str:
    if msg.kind == "dh_public":
        text = f"DH public {dh.short_hex(msg.payload, 8)}"
    else:
        text = f"AES-CBC ciphertext, {len(msg.payload[1])} bytes"
    return text + (f", signature {msg.signature[:6].hex()}..." if msg.signature else "")


class SimulatedChannel:
    """In-memory channel. An optional interceptor sees (and may replace) every message."""

    def __init__(self, interceptor: "Attacker | None" = None):
        self.interceptor = interceptor
        self.log: list[str] = []

    def send(self, msg: Message) -> Message:
        self.log.append(f"{msg.src} -> {msg.dst}: {describe(msg)}")
        if self.interceptor is not None:
            delivered = self.interceptor.intercept(msg)
            if delivered is not msg:
                self.log.append(f"    !! intercepted by Attacker; {msg.dst} receives instead: {describe(delivered)}")
            return delivered
        return msg


class HandshakeAborted(Exception):
    """Raised by a party that rejects a peer's DH value."""


def signed_bytes(role: str, public_value: int) -> bytes:
    """What gets signed: context label + claimed identity + DH public value."""
    return b"SECURE-REC-DH-v1|" + role.encode() + b"|" + dh.int_to_bytes(public_value)


# ---------------------------------------------------------------------- attacker
class Attacker:
    """Sits between Sender and Receiver and runs one DH exchange with each."""

    def __init__(self, own_rsa: RSA.RsaKey | None = None, strategy: str = "substitute",
                 tamper: Callable[[bytes], bytes] | None = None):
        self.with_sender = dh.DHParty("Attacker (posing as Receiver)")
        self.with_receiver = dh.DHParty("Attacker (posing as Sender)")
        self.sender_public: int | None = None
        self.receiver_public: int | None = None
        self.own_rsa = own_rsa
        # "substitute": replace DH values, forward any signature unchanged
        # "resign":     replace DH values and sign them with the attacker's own RSA key
        self.strategy = strategy
        self.tamper = tamper
        self.captured: list[bytes] = []  # plaintexts read by the attacker (memory only)

    def key_with_sender(self) -> bytes:
        return self.with_sender.session_key(self.sender_public)

    def key_with_receiver(self) -> bytes:
        return self.with_receiver.session_key(self.receiver_public)

    def intercept(self, msg: Message) -> Message:
        if msg.kind == "dh_public":
            if msg.src == "Sender":
                self.sender_public, fake = msg.payload, self.with_receiver.public
            else:
                self.receiver_public, fake = msg.payload, self.with_sender.public
            signature = msg.signature
            if signature is not None and self.strategy == "resign":
                signature = sign_pss(signed_bytes(msg.src, fake), self.own_rsa)
            return Message(msg.src, msg.dst, msg.kind, fake, signature)

        if msg.kind == "ciphertext" and msg.src == "Sender":
            iv, ct = msg.payload
            plaintext = cu.aes_cbc_decrypt(ct, self.key_with_sender(), iv)
            self.captured.append(plaintext)
            if self.tamper is not None:
                plaintext = self.tamper(plaintext)
            return Message(msg.src, msg.dst, msg.kind, cu.aes_cbc_encrypt(plaintext, self.key_with_receiver()))
        return msg


# --------------------------------------------------------------------- protocol
def handshake(channel: SimulatedChannel, sender: dh.DHParty, receiver: dh.DHParty,
              identities: dict[str, RSA.RsaKey] | None = None) -> tuple[bytes, bytes]:
    """Run DH over ``channel``. With ``identities`` each value is signed and verified.

    ``identities`` maps "Sender"/"Receiver" to their long-term RSA keys; each
    side verifies against the peer's *trusted public* key only.
    """
    def outgoing(role: str, party: dh.DHParty, dst: str) -> Message:
        sig = sign_pss(signed_bytes(role, party.public), identities[role]) if identities else None
        return Message(role, dst, "dh_public", party.public, sig)

    def check(msg: Message, expected_role: str) -> None:
        if identities is None:
            return
        trusted_public = identities[expected_role].publickey()
        if msg.signature is None or not verify_pss(signed_bytes(expected_role, msg.payload),
                                                   msg.signature, trusted_public):
            raise HandshakeAborted(f"signature on {expected_role}'s DH value is INVALID")

    at_receiver = channel.send(outgoing("Sender", sender, "Receiver"))
    check(at_receiver, "Sender")
    at_sender = channel.send(outgoing("Receiver", receiver, "Sender"))
    check(at_sender, "Receiver")
    return sender.session_key(at_sender.payload), receiver.session_key(at_receiver.payload)


def transmit(channel: SimulatedChannel, sender_key: bytes, receiver_key: bytes, data: bytes) -> bytes:
    """Sender encrypts with its key; whatever arrives is decrypted by the Receiver."""
    delivered = channel.send(Message("Sender", "Receiver", "ciphertext", cu.aes_cbc_encrypt(data, sender_key)))
    iv, ct = delivered.payload
    return cu.aes_cbc_decrypt(ct, receiver_key, iv)


def _tamper_grades(data: bytes) -> bytes:
    return TAMPERED_ORDER if data == ORIGINAL_ORDER else data


# --------------------------------------------------------------------- phases
def phase1_attack(payload: bytes) -> tuple[dict, list[str]]:
    sender, receiver = dh.DHParty("Sender"), dh.DHParty("Receiver")
    attacker = Attacker(tamper=_tamper_grades)
    channel = SimulatedChannel(interceptor=attacker)
    channel.log.append("--- DH handshake (no authentication) ---")
    k_sender, k_receiver = handshake(channel, sender, receiver)
    k_att_s, k_att_r = attacker.key_with_sender(), attacker.key_with_receiver()

    channel.log.append("--- Sender transmits the selected file ---")
    received_file = transmit(channel, k_sender, k_receiver, payload)
    channel.log.append("--- Sender transmits a short instruction ---")
    received_order = transmit(channel, k_sender, k_receiver, ORIGINAL_ORDER)

    captured_file = attacker.captured[0]
    return {
        "sender_key_fp": key_fingerprint(k_sender),
        "receiver_key_fp": key_fingerprint(k_receiver),
        "attacker_key_with_sender_fp": key_fingerprint(k_att_s),
        "attacker_key_with_receiver_fp": key_fingerprint(k_att_r),
        "attacker_has_sender_key": k_att_s == k_sender,
        "attacker_has_receiver_key": k_att_r == k_receiver,
        "victims_share_key": k_sender == k_receiver,
        "file_read_by_attacker": captured_file == payload,
        "captured_file_sha256": sha256_bytes(captured_file),
        "captured_file_bytes": len(captured_file),
        "receiver_file_intact": received_file == payload,
        "order_sent": ORIGINAL_ORDER.decode(),
        "order_received": received_order.decode(errors="replace"),
        "order_tampered_undetected": received_order == TAMPERED_ORDER,
    }, channel.log


def phase2_mitigation(identities: dict[str, RSA.RsaKey]) -> tuple[dict, list[str]]:
    trusted = {"Sender": identities["sender"], "Receiver": identities["receiver"]}
    log: list[str] = []
    outcomes = {}
    for strategy, label in (("substitute", "attacker forwards original signatures"),
                            ("resign", "attacker re-signs with its own RSA key")):
        channel = SimulatedChannel(Attacker(own_rsa=identities["attacker"], strategy=strategy))
        channel.log.append(f"--- Authenticated DH, {label} ---")
        try:
            handshake(channel, dh.DHParty("Sender"), dh.DHParty("Receiver"), trusted)
            outcomes[strategy] = "NOT DETECTED"
        except HandshakeAborted as exc:
            channel.log.append(f"    Receiver ABORTS handshake: {exc}")
            outcomes[strategy] = "DETECTED - handshake aborted"
        log += channel.log

    channel = SimulatedChannel()
    channel.log.append("--- Authenticated DH, no attacker ---")
    k_s, k_r = handshake(channel, dh.DHParty("Sender"), dh.DHParty("Receiver"), trusted)
    channel.log.append(f"    signatures valid; both derived key fp {key_fingerprint(k_s)}")
    log += channel.log
    return {
        "attack_forward_signature": outcomes["substitute"],
        "attack_resign_own_key": outcomes["resign"],
        "honest_authenticated_keys_match": k_s == k_r,
    }, log


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        identity_keys: dict[str, RSA.RsaKey] | None = None) -> TaskResult:
    """``identity_keys`` ({"sender","receiver","attacker"} -> RSA key) may be injected for tests."""
    info = describe_file(resolve_input(input_path))
    payload = read_file_bytes(info.path)
    out_dir = task_output_dir(TASK_ID, output_root)
    identities = identity_keys or {r: generate_rsa_keypair() for r in ("sender", "receiver", "attacker")}

    p1, log1 = phase1_attack(payload)
    p2, log2 = phase2_mitigation(identities)

    attack_worked = (p1["attacker_has_sender_key"] and p1["attacker_has_receiver_key"]
                     and not p1["victims_share_key"] and p1["file_read_by_attacker"]
                     and p1["receiver_file_intact"] and p1["order_tampered_undetected"])
    mitigation_worked = (p2["attack_forward_signature"].startswith("DETECTED")
                         and p2["attack_resign_own_key"].startswith("DETECTED")
                         and p2["honest_authenticated_keys_match"])

    transcript = out_dir / "transcript.txt"
    transcript.write_text(
        "SIMULATED ATTACK - in-memory only, no real network traffic.\n\n"
        "PHASE 1: MITM on unauthenticated Diffie-Hellman\n" + "\n".join(log1) +
        "\n\nPHASE 2: Mitigation - signed (authenticated) Diffie-Hellman\n" + "\n".join(log2) + "\n",
        encoding="utf-8")

    yes = lambda b: "TRUE" if b else "FALSE"  # noqa: E731
    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if attack_worked and mitigation_worked else Status.FAIL,
                        artifacts=[transcript])
    if result.status is Status.FAIL:
        result.reason = "Simulation did not behave as expected."
    result.add("NOTICE", "Intentionally simulated attack (in-memory, no network activity)")
    result.add("Payload", f"{info.name} ({info.human_size})")
    result.add("[Phase 1] Sender's key fp", f"{p1['sender_key_fp']} (Sender thinks: shared with Receiver)")
    result.add("[Phase 1] Receiver's key fp", f"{p1['receiver_key_fp']} (Receiver thinks: shared with Sender)")
    result.add("[Phase 1] Sender & Receiver share a key", yes(p1["victims_share_key"]))
    result.add("[Phase 1] Attacker key with Sender", f"{p1['attacker_key_with_sender_fp']} = Sender's key: "
                                                     f"{yes(p1['attacker_has_sender_key'])}")
    result.add("[Phase 1] Attacker key with Receiver", f"{p1['attacker_key_with_receiver_fp']} = Receiver's key: "
                                                       f"{yes(p1['attacker_has_receiver_key'])}")
    result.add("[Phase 1] Attacker decrypted the file", f"{yes(p1['file_read_by_attacker'])} "
                                                        f"({p1['captured_file_bytes']} bytes, SHA-256 "
                                                        f"{p1['captured_file_sha256'][:16]}...)")
    result.add("[Phase 1] Receiver noticed anything", "NO - file arrived intact after re-encryption"
               if p1["receiver_file_intact"] else "file corrupted")
    result.add("[Phase 1] Message sent", p1["order_sent"])
    result.add("[Phase 1] Message received", f"{p1['order_received']}  (altered, undetected: "
                                             f"{yes(p1['order_tampered_undetected'])})")
    result.add("[Phase 2] Identity keys", f"RSA-{identities['sender'].size_in_bits()} Sender fp "
                                          f"{public_key_fingerprint(identities['sender'])}, Receiver fp "
                                          f"{public_key_fingerprint(identities['receiver'])}")
    result.add("[Phase 2] Attack: forward signature", p2["attack_forward_signature"])
    result.add("[Phase 2] Attack: re-sign with own key", p2["attack_resign_own_key"])
    result.add("[Phase 2] Honest signed exchange", "PASS - keys match" if p2["honest_authenticated_keys_match"]
               else "FAIL")
    result.add("Attack demonstrated", yes(attack_worked))
    result.add("Mitigation effective", yes(mitigation_worked))
    result.data = {"phase1": p1, "phase2": p2, "attack_demonstrated": attack_worked,
                   "mitigation_effective": mitigation_worked}
    result.details = (
        "Sender <--K1--> Attacker <--K2--> Receiver\n"
        "Plain DH proves only that you share a key with *someone*, not with whom. The\n"
        "attacker swapped in its own public values and ran two separate exchanges. Every\n"
        "message was decrypted with K1 and re-encrypted with K2. Both victims' checks passed,\n"
        "and a changed instruction was delivered undetected.\n"
        "Mitigation: each DH public value is signed with a long-term private key, and the\n"
        "peer checks it against a public key it already trusts (distributed out of band or\n"
        "via an X.509 certificate from a CA, Task 11). The attacker cannot sign as the\n"
        "Sender. Forwarding the old signature fails because the value changed, and a\n"
        "signature from its own key fails against the trusted key. This is how TLS 1.3\n"
        "(ECDHE + CertificateVerify), SSH host keys and IKE/IPsec stop this attack. Real\n"
        "protocols sign the whole handshake transcript (both values plus nonces) to prevent\n"
        "replay too; this demo signs each value with a role label."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
