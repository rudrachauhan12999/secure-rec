"""Task 1: AES-128-CBC and 3-DES-CBC on arbitrary file types."""

from __future__ import annotations

import json

import pytest

from core.results import Status
from tasks import task01_symmetric as t1


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image", "jpeg_image"])
def test_round_trip_for_any_file_type(fixture, request, out_root):
    src = request.getfixturevalue(fixture)
    result = t1.run(src, output_root=out_root)
    assert result.status is Status.PASS, result.reason
    original = src.read_bytes()
    out = out_root / "task01"
    for tag, iv_len in (("aes128cbc", 16), ("3descbc", 8)):
        enc = (out / f"{src.name}.{tag}.enc").read_bytes()
        dec = (out / f"decrypted_{tag}_{src.name}").read_bytes()
        assert dec == original                                   # exact byte recovery
        assert original not in enc                                # ciphertext is not plaintext
        assert (len(enc) - iv_len) % (16 if tag == "aes128cbc" else 8) == 0
    assert all(r["match"] for r in result.data["runs"])
    assert (out / "report.txt").exists() and (out / "report.json").exists()


def test_default_input_is_student_dataset(out_root):
    result = t1.run(output_root=out_root)
    assert result.status is Status.PASS
    assert result.data["file"] == "student_records.txt"


def test_keys_never_written_to_reports(monkeypatch, out_root, sample_file):
    aes_key, tdes_key = b"\x11" * 16, bytes.fromhex("0123456789abcdeffedcba987654321089abcdef01234567")
    monkeypatch.setitem(t1.CIPHERS, "AES-128-CBC", (lambda: aes_key, *t1.CIPHERS["AES-128-CBC"][1:]))
    monkeypatch.setitem(t1.CIPHERS, "3-DES-CBC", (lambda: tdes_key, *t1.CIPHERS["3-DES-CBC"][1:]))
    t1.run(sample_file, output_root=out_root)
    report = (out_root / "task01" / "report.txt").read_text() + (out_root / "task01" / "report.json").read_text()
    for key in (aes_key, tdes_key):
        assert key.hex() not in report.lower()
    json.loads((out_root / "task01" / "report.json").read_text())  # valid JSON


def test_missing_file_reports_error_instead_of_crashing(tmp_path, out_root):
    result = t1.run(tmp_path / "does_not_exist.txt", output_root=out_root)
    assert result.status is Status.ERROR and "not found" in result.reason
