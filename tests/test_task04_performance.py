"""Task 4: AES vs 3-DES benchmark (few repetitions to keep the test fast)."""

from __future__ import annotations

import csv

from core.hashing import sha256_file
from core.results import Status
from tasks import task04_performance as t4


def test_benchmark_files_are_reproducible(tmp_path):
    a = t4.generate_benchmark_files(tmp_path / "a")
    b = t4.generate_benchmark_files(tmp_path / "b")
    for label, size in t4.BENCH_SIZES.items():
        assert a[label].stat().st_size == size
        assert sha256_file(a[label]) == sha256_file(b[label])


def test_benchmark_produces_table_csv_and_chart(tmp_path, out_root, sample_file):
    result = t4.run(sample_file, output_root=out_root, bench_dir=tmp_path / "bench", repeats=5)
    assert result.status is Status.COMPLETED, result.reason
    rows = result.data["rows"]
    assert len(rows) == 6 and all(r["roundtrip_ok"] for r in rows)
    assert {r["cipher"] for r in rows} == {"AES-128-CBC", "3-DES-CBC"}
    assert all(r["encrypt_median_ms"] > 0 and r["decrypt_median_ms"] > 0 for r in rows)

    out = out_root / "task04"
    with open(out / "benchmark_results.csv", newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 6
    chart = out / "benchmark_chart.png"
    assert chart.exists() and chart.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert "100 KB" in (out / "benchmark_table.txt").read_text()


def test_aes_is_faster_than_3des_on_100kb(tmp_path, out_root):
    result = t4.run(output_root=out_root, bench_dir=tmp_path / "bench", repeats=15)
    assert result.data["speedup"]["100 KB"]["encrypt"] > 1
    assert result.data["speedup"]["100 KB"]["decrypt"] > 1


def test_invalid_repeats(out_root, tmp_path):
    result = t4.run(output_root=out_root, bench_dir=tmp_path, repeats=1)
    assert result.status is Status.ERROR
