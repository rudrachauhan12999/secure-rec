"""Task 5: RSA + AES hybrid encryption."""

from __future__ import annotations

import pytest

from core.hybrid import HybridPackage, hybrid_decrypt
from core.results import Status
from tasks import task05_hybrid as t5


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image", "jpeg_image"])
def test_hybrid_round_trip_for_any_file(fixture, request, out_root, rsa_key):
    src = request.getfixturevalue(fixture)
    result = t5.run(src, output_root=out_root, receiver_key=rsa_key, check_wrong_key=False)
    assert result.status is Status.PASS, result.reason
    out = out_root / "task05"
    original = src.read_bytes()
    assert (out / f"recovered_{src.name}").read_bytes() == original
    assert result.data["match"] and result.data["session_key_recovered"]
    assert result.data["wrapped_key_bytes"] == 256

    # The transferred package is independently decryptable with the private key ...
    blob = (out / "transfer" / f"{src.name}.hybrid").read_bytes()
    assert hybrid_decrypt(HybridPackage.from_bytes(blob), rsa_key) == original
    # ... and does not contain the plaintext.
    assert original[:64] not in blob


def test_default_run_generates_keys_and_rejects_wrong_key(out_root):
    result = t5.run(output_root=out_root)  # student dataset, fresh RSA-2048 pair
    assert result.status is Status.PASS, result.reason
    assert result.data["rsa_bits"] == 2048
    assert result.data["wrong_key_rejected"] is True


def test_no_private_key_or_session_key_saved(out_root, rsa_key, sample_file, monkeypatch):
    session_key = bytes(range(16))
    monkeypatch.setattr("core.hybrid.generate_aes_key", lambda bits=128: session_key)
    t5.run(sample_file, output_root=out_root, receiver_key=rsa_key, check_wrong_key=False)
    out = out_root / "task05"
    private_pem = rsa_key.export_key().decode()
    private_body = "".join(private_pem.splitlines()[1:-1])[:64]
    for f in out.rglob("*"):
        if f.is_file():
            content = f.read_bytes()
            assert b"PRIVATE KEY" not in content
            assert private_body.encode() not in content
            assert session_key not in content                  # raw key bytes
            assert session_key.hex().encode() not in content   # hex-encoded key
    assert b"PUBLIC KEY" in (out / "receiver_public_key.pem").read_bytes()


def test_invalid_input_is_reported(tmp_path, out_root, rsa_key):
    result = t5.run(tmp_path / "missing.bin", output_root=out_root, receiver_key=rsa_key)
    assert result.status is Status.ERROR
