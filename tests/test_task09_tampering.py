"""Task 9: tampering detection."""

from __future__ import annotations

import pytest

from core.hashing import sha256_bytes
from core.results import Status
from tasks import task09_tampering as t9


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image", "jpeg_image"])
def test_genuine_verified_and_all_tampering_detected(fixture, request, out_root):
    src = request.getfixturevalue(fixture)
    result = t9.run(src, output_root=out_root)
    assert result.status is Status.PASS, result.reason
    cases = result.data["cases"]
    assert cases["A"]["match"] is True and cases["A"]["verdict"] == "INTEGRITY VERIFIED"
    for cid in ("B1", "B2", "C"):
        assert cases[cid]["match"] is False
        assert cases[cid]["verdict"].startswith("TAMPERING DETECTED")
    assert result.data["reference_sha256"] == sha256_bytes(src.read_bytes())


def test_report_shows_required_evidence(sample_file, out_root):
    result = t9.run(sample_file, output_root=out_root)
    text = (out_root / "task09" / "report.txt").read_text()
    for needle in ("Original hash (reference)", "received hash", "MATCH", "FALSE", "TAMPERING DETECTED",
                   "INTEGRITY VERIFIED"):
        assert needle in text
    assert result.data["cases"]["B1"]["plaintext_bytes_changed"] == 1   # silent targeted bit-flip


def test_tampered_data_is_kept_not_repaired(binary_file, out_root):
    t9.run(binary_file, output_root=out_root)
    out = out_root / "task09"
    name = binary_file.name
    original = binary_file.read_bytes()
    sent = (out / f"transmitted_{name}.enc").read_bytes()
    for tampered in (f"B1_tampered_iv_{name}.enc", f"B2_tampered_ciphertext_{name}.enc"):
        diff = sum(a != b for a, b in zip(sent, (out / tampered).read_bytes()))
        assert diff == 1
    assert (out / f"A_recovered_{name}").read_bytes() == original
    assert (out / f"B1_received_{name}").read_bytes() != original
    assert (out / f"C_modified_{name}").read_bytes() != original
    assert len((out / "tamper_log.csv").read_text().strip().splitlines()) == 5


def test_tiny_file_padding_failure_still_counts_as_detected(tmp_path, out_root):
    p = tmp_path / "one.bin"
    p.write_bytes(b"\x42")
    result = t9.run(p, output_root=out_root)
    assert result.status is Status.PASS
    assert result.data["cases"]["B2"]["match"] is False


def test_tamper_helper_bounds():
    data, old, new = t9.tamper(b"\x00\x10", 1, 0xFF)
    assert data == b"\x00\xef" and (old, new) == (0x10, 0xEF)
    with pytest.raises(IndexError):
        t9.tamper(b"ab", 5, 1)


def test_missing_file_is_error(tmp_path, out_root):
    assert t9.run(tmp_path / "none.txt", output_root=out_root).status is Status.ERROR
