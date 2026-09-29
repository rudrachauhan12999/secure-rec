"""Task 8: SHA-256 integrity verification."""

from __future__ import annotations

import hashlib
import shutil

import pytest

from core.results import Status
from tasks import task08_sha256 as t8


@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image", "jpeg_image"])
def test_simulated_transfer_verifies_integrity(fixture, request, out_root):
    src = request.getfixturevalue(fixture)
    result = t8.run(src, output_root=out_root)
    assert result.status is Status.PASS, result.reason
    expected = hashlib.sha256(src.read_bytes()).hexdigest()
    assert result.data["sha256_original"] == result.data["sha256_received"] == expected
    assert (out_root / "task08" / f"recovered_{src.name}").read_bytes() == src.read_bytes()
    sums = (out_root / "task08" / "sha256sums.txt").read_text().splitlines()
    assert sums[0] == f"{expected}  {src.name}"


def test_identical_received_file_verifies(tmp_path, sample_file, out_root):
    copy = tmp_path / "received_copy.txt"
    shutil.copy(sample_file, copy)
    result = t8.run(sample_file, output_root=out_root, received_path=copy)
    assert result.status is Status.PASS and result.data["match"]


def test_single_byte_change_is_reported(tmp_path, binary_file, out_root):
    data = bytearray(binary_file.read_bytes())
    data[len(data) // 2] ^= 0x01
    changed = tmp_path / "changed.bin"
    changed.write_bytes(bytes(data))
    result = t8.run(binary_file, output_root=out_root, received_path=changed)
    assert result.status is Status.FAIL
    assert result.data["match"] is False
    assert dict(result.summary)["MATCH"] == "FALSE"
    assert result.data["sha256_original"] != result.data["sha256_received"]


def test_missing_received_file_is_error(tmp_path, sample_file, out_root):
    result = t8.run(sample_file, output_root=out_root, received_path=tmp_path / "nope.bin")
    assert result.status is Status.ERROR
