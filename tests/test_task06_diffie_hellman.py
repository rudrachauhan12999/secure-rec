"""Task 6: Diffie-Hellman key exchange."""

from __future__ import annotations

import json

from core import diffie_hellman as dh
from core.results import Status
from tasks import task06_diffie_hellman as t6


def test_both_parties_derive_same_secret(out_root):
    result = t6.run(output_root=out_root)
    assert result.status is Status.PASS, result.reason
    assert result.data["secrets_match"] and result.data["keys_match"] and result.data["message_roundtrip"]
    assert result.data["p_bits"] == 2048


def test_transcript_contains_only_public_values(out_root):
    t6.run(output_root=out_root)
    transcript = json.loads((out_root / "task06" / "public_transcript.json").read_text())
    fields = [m["field"] for m in transcript["messages"]]
    assert "A = g^a mod p" in fields and "B = g^b mod p" in fields
    assert not any("private" in f.lower() or "secret" in f.lower() for f in fields)


def test_private_values_and_shared_secret_not_written(out_root, monkeypatch):
    fixed = iter([0x1234567890ABCDEF1234567890ABCDEF, 0xFEDCBA0987654321FEDCBA0987654321])
    monkeypatch.setattr(dh.secrets, "randbelow", lambda n: next(fixed))
    result = t6.run(output_root=out_root)
    a, b = 0x1234567890ABCDEF1234567890ABCDEF + 2, 0xFEDCBA0987654321FEDCBA0987654321 + 2
    shared = pow(pow(dh.G, a, dh.P), b, dh.P)
    text = "".join(p.read_text().lower() for p in (out_root / "task06").iterdir())
    for secret in (a, b, shared):
        assert format(secret, "x") not in text and str(secret) not in text
    assert result.status is Status.PASS


def test_each_run_uses_fresh_random_values(out_root):
    r1, r2 = t6.run(output_root=out_root), t6.run(output_root=out_root)
    assert r1.data["shared_secret_fingerprint"] != r2.data["shared_secret_fingerprint"]
