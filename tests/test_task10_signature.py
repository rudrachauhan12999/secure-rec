"""Task 10: digital signatures."""

from __future__ import annotations

import pytest
from Crypto.PublicKey import RSA

from core.results import Status
from core.signatures import verify_pss
from tasks import task10_signature as t10

EXPECTED = {"original_file_genuine_key": True, "modified_file": False,
            "impostor_public_key": False, "altered_signature": False}


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image"])
def test_valid_then_invalid_after_modification(fixture, request, out_root, rsa_identities):
    src = request.getfixturevalue(fixture)
    result = t10.run(src, output_root=out_root, signing_key=rsa_identities["sender"],
                     impostor_key=rsa_identities["attacker"])
    assert result.status is Status.PASS, result.reason
    assert result.data["checks"] == EXPECTED

    out = out_root / "task10"
    sig = (out / f"{src.name}.sig").read_bytes()
    pub = RSA.import_key((out / "sender_public_key.pem").read_bytes())
    assert len(sig) == 256
    assert verify_pss(src.read_bytes(), sig, pub)                              # independently verifiable
    assert not verify_pss((out / f"modified_{src.name}").read_bytes(), sig, pub)


def test_default_run_generates_keys(out_root):
    result = t10.run(output_root=out_root)
    assert result.status is Status.PASS and result.data["checks"] == EXPECTED


def test_report_distinguishes_security_properties(sample_file, out_root, rsa_identities):
    t10.run(sample_file, output_root=out_root, signing_key=rsa_identities["sender"],
            impostor_key=rsa_identities["attacker"])
    text = (out_root / "task10" / "report.txt").read_text()
    for needle in ("Confidentiality", "Integrity", "Authenticity / non-repudiation", "VALID", "INVALID"):
        assert needle in text


def test_public_key_cannot_sign(sample_file, out_root, rsa_identities):
    result = t10.run(sample_file, output_root=out_root, signing_key=rsa_identities["sender"].publickey(),
                     impostor_key=rsa_identities["attacker"])
    assert result.status is Status.ERROR
