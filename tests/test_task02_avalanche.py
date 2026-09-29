"""Task 2: avalanche effect."""

from __future__ import annotations

from core import crypto_utils as cu
from core.results import Status
from tasks import task02_avalanche as t2


def test_one_bit_flip_changes_about_half_of_ciphertext(sample_file, out_root):
    result = t2.run(sample_file, output_root=out_root)
    assert result.status is Status.COMPLETED, result.reason
    d = result.data
    # With ~550k ciphertext bits the proportion is tightly concentrated around 50 %.
    assert 48.0 < d["changed_percent_total"] < 52.0
    assert 30.0 < d["single_block_changed_percent"] < 70.0
    assert 45.0 < d["sweep_mean_percent"] < 55.0

    out = out_root / "task02"
    original, modified = sample_file.read_bytes(), (out / "modified_student_records.txt").read_bytes()
    assert cu.count_differing_bits(original, modified) == 1
    assert (out / "ciphertext_original.bin").read_bytes() != (out / "ciphertext_modified.bin").read_bytes()
    assert len((out / "single_block_bit_sweep.csv").read_text().strip().splitlines()) == 129


def test_cbc_blocks_before_the_change_are_identical(binary_file, out_root):
    bit = 10 * 128 + 5  # inside block 10
    result = t2.run(binary_file, output_root=out_root, bit_index=bit)
    d = result.data
    assert d["changed_block_index"] == 10
    assert d["bits_changed_before_changed_block"] == 0
    assert 40.0 < d["changed_percent_from_changed_block"] < 60.0


def test_bit_in_last_partial_block(tmp_path, out_root):
    p = tmp_path / "short.txt"
    p.write_bytes(b"20 bytes of content!")
    result = t2.run(p, output_root=out_root, bit_index=20 * 8 - 1)
    assert result.status is Status.COMPLETED and result.data["changed_block_index"] == 1


def test_invalid_bit_index_is_reported(sample_file, out_root):
    result = t2.run(sample_file, output_root=out_root, bit_index=10**9)
    assert result.status is Status.ERROR and "bit_index" in result.reason
