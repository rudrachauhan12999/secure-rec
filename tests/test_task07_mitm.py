"""Task 7: simulated Diffie-Hellman man-in-the-middle attack and mitigation."""

from __future__ import annotations

import pytest

from core import diffie_hellman as dh
from core.results import Status
from tasks import task07_mitm as t7


def test_unauthenticated_handshake_gives_attacker_both_keys():
    sender, receiver, attacker = dh.DHParty("Sender"), dh.DHParty("Receiver"), t7.Attacker()
    k_s, k_r = t7.handshake(t7.SimulatedChannel(attacker), sender, receiver)
    assert k_s != k_r                                   # victims do NOT share a key
    assert attacker.key_with_sender() == k_s
    assert attacker.key_with_receiver() == k_r


def test_attacker_reads_and_alters_traffic(binary_file):
    payload = binary_file.read_bytes()
    attacker = t7.Attacker(tamper=lambda d: d[::-1])
    channel = t7.SimulatedChannel(attacker)
    k_s, k_r = t7.handshake(channel, dh.DHParty("Sender"), dh.DHParty("Receiver"))
    received = t7.transmit(channel, k_s, k_r, payload)
    assert attacker.captured == [payload]               # attacker saw the plaintext
    assert received == payload[::-1]                    # receiver got the altered data


def test_no_attacker_means_shared_key():
    k_s, k_r = t7.handshake(t7.SimulatedChannel(), dh.DHParty("Sender"), dh.DHParty("Receiver"))
    assert k_s == k_r


@pytest.mark.parametrize("strategy", ["substitute", "resign"])
def test_authenticated_handshake_detects_mitm(strategy, rsa_identities):
    trusted = {"Sender": rsa_identities["sender"], "Receiver": rsa_identities["receiver"]}
    attacker = t7.Attacker(own_rsa=rsa_identities["attacker"], strategy=strategy)
    with pytest.raises(t7.HandshakeAborted):
        t7.handshake(t7.SimulatedChannel(attacker), dh.DHParty("Sender"), dh.DHParty("Receiver"), trusted)


def test_authenticated_handshake_succeeds_without_attacker(rsa_identities):
    trusted = {"Sender": rsa_identities["sender"], "Receiver": rsa_identities["receiver"]}
    k_s, k_r = t7.handshake(t7.SimulatedChannel(), dh.DHParty("Sender"), dh.DHParty("Receiver"), trusted)
    assert k_s == k_r


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file"])
def test_full_simulation(fixture, request, out_root, rsa_identities):
    src = request.getfixturevalue(fixture)
    result = t7.run(src, output_root=out_root, identity_keys=rsa_identities)
    assert result.status is Status.PASS, result.reason
    p1, p2 = result.data["phase1"], result.data["phase2"]
    assert p1["attacker_has_sender_key"] and p1["attacker_has_receiver_key"]
    assert not p1["victims_share_key"]
    assert p1["file_read_by_attacker"] and p1["receiver_file_intact"]
    assert p1["order_tampered_undetected"]
    assert p2["attack_forward_signature"].startswith("DETECTED")
    assert p2["attack_resign_own_key"].startswith("DETECTED")
    assert p2["honest_authenticated_keys_match"]

    # Intercepted plaintext must not be written to disk - only hashes/sizes.
    chunk = src.read_bytes()[100:164]
    for f in (out_root / "task07").iterdir():
        assert chunk not in f.read_bytes()
    assert "SIMULATED" in (out_root / "task07" / "transcript.txt").read_text()
