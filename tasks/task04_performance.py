"""Task 4 - AES vs 3-DES performance benchmark.

The benchmark does NOT use the user's selected file: it generates controlled
input files of 1 KB, 10 KB and 100 KB from a fixed seed, so every run (on any
machine) measures exactly the same bytes.  The benchmark content only needs
to be reproducible, not secret, so a seeded ``random.Random`` is appropriate
here; keys and IVs still come from the CSPRNG.

Methodology
-----------
* Ciphers: AES-128-CBC and 3-DES (3-key) CBC, PKCS#7 padding.
* Each timed operation includes cipher-object creation + (un)padding + the
  (de)cryption itself, i.e. what an application actually pays per file.
* A few warm-up runs are discarded, then ``repeats`` timed runs are taken
  with ``time.perf_counter_ns``; the median is reported (robust to OS
  scheduling noise), mean and standard deviation are kept in the CSV.
* Every decryption is checked against the input.

Absolute numbers depend on the CPU (AES benefits from AES-NI hardware
instructions); the relative AES : 3-DES ratio is the meaningful result.
"""

from __future__ import annotations

import csv
import json
import platform
import random
import statistics
import time
from pathlib import Path
from typing import Callable

import Crypto
from matplotlib.figure import Figure

from core import crypto_utils as cu
from core.config import BENCHMARKS_DIR
from core.file_handler import task_output_dir, write_file_bytes
from core.hashing import sha256_bytes
from core.key_manager import generate_3des_key, generate_aes_key, generate_iv
from core.results import Status, TaskResult, guarded
from tasks.common import cli_main

TASK_ID = "task04"
TITLE = "Task 4 - AES vs 3-DES Performance"

BENCH_SIZES: dict[str, int] = {"1 KB": 1024, "10 KB": 10 * 1024, "100 KB": 100 * 1024}
BENCH_SEED = 20240401  # fixed so the generated benchmark files are identical every run
DEFAULT_REPEATS = 200
WARMUP = 10

# Categorical colours (validated adjacent pair: slot 1 blue, slot 2 orange).
COLORS = {"AES-128-CBC": "#2a78d6", "3-DES-CBC": "#eb6834"}
TEXT, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def generate_benchmark_files(bench_dir: Path) -> dict[str, Path]:
    """Create (or recreate identically) the three controlled benchmark inputs."""
    data_dir = bench_dir / "data"
    files = {}
    for label, size in BENCH_SIZES.items():
        rng = random.Random(BENCH_SEED + size)
        files[label] = write_file_bytes(data_dir / f"bench_{size // 1024}KB.bin", rng.randbytes(size))
    return files


def _cipher_ops(name: str) -> tuple[Callable[[bytes], bytes], Callable[[bytes], bytes]]:
    """Return encrypt/decrypt callables with a fixed key+IV for a fair, repeatable loop."""
    if name == "AES-128-CBC":
        key, iv = generate_aes_key(128), generate_iv(cu.AES_BLOCK)
        return (lambda d: cu.aes_cbc_encrypt(d, key, iv)[1]), (lambda c: cu.aes_cbc_decrypt(c, key, iv))
    key, iv = generate_3des_key(), generate_iv(cu.TDES_BLOCK)
    return (lambda d: cu.tdes_cbc_encrypt(d, key, iv)[1]), (lambda c: cu.tdes_cbc_decrypt(c, key, iv))


def _time_ms(fn: Callable[[bytes], bytes], arg: bytes, repeats: int) -> tuple[list[float], bytes]:
    for _ in range(WARMUP):
        out = fn(arg)
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        out = fn(arg)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples, out


def benchmark(files: dict[str, Path], repeats: int = DEFAULT_REPEATS) -> list[dict]:
    rows = []
    for label, path in files.items():
        data = path.read_bytes()
        for cipher in COLORS:
            enc, dec = _cipher_ops(cipher)
            enc_s, ct = _time_ms(enc, data, repeats)
            dec_s, pt = _time_ms(dec, ct, repeats)
            enc_med, dec_med = statistics.median(enc_s), statistics.median(dec_s)
            rows.append({
                "size_label": label,
                "size_bytes": len(data),
                "cipher": cipher,
                "repeats": repeats,
                "encrypt_median_ms": round(enc_med, 5),
                "encrypt_mean_ms": round(statistics.mean(enc_s), 5),
                "encrypt_stdev_ms": round(statistics.stdev(enc_s), 5),
                "decrypt_median_ms": round(dec_med, 5),
                "decrypt_mean_ms": round(statistics.mean(dec_s), 5),
                "decrypt_stdev_ms": round(statistics.stdev(dec_s), 5),
                "encrypt_MBps": round(len(data) / 1e6 / (enc_med / 1000), 2),
                "decrypt_MBps": round(len(data) / 1e6 / (dec_med / 1000), 2),
                "roundtrip_ok": pt == data,
            })
    return rows


def format_table(rows: list[dict]) -> str:
    head = f"{'Size':>7} | {'Cipher':<12} | {'Enc median ms':>13} | {'Dec median ms':>13} | {'Enc MB/s':>9} | {'Dec MB/s':>9}"
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append(f"{r['size_label']:>7} | {r['cipher']:<12} | {r['encrypt_median_ms']:>13.4f} | "
                     f"{r['decrypt_median_ms']:>13.4f} | {r['encrypt_MBps']:>9.1f} | {r['decrypt_MBps']:>9.1f}")
    return "\n".join(lines)


def speedups(rows: list[dict]) -> dict[str, dict[str, float]]:
    """How many times faster AES is than 3-DES, per size and operation."""
    out = {}
    for label in BENCH_SIZES:
        a = next(r for r in rows if r["size_label"] == label and r["cipher"] == "AES-128-CBC")
        t = next(r for r in rows if r["size_label"] == label and r["cipher"] == "3-DES-CBC")
        out[label] = {
            "encrypt": round(t["encrypt_median_ms"] / a["encrypt_median_ms"], 1),
            "decrypt": round(t["decrypt_median_ms"] / a["decrypt_median_ms"], 1),
        }
    return out


def plot_chart(rows: list[dict], path: Path) -> Path:
    """One panel per file size (own linear axis), grouped bars: encryption & decryption."""
    fig = Figure(figsize=(11, 4.2), dpi=150, facecolor="white")
    axes = fig.subplots(1, len(BENCH_SIZES))
    ops = [("encrypt_median_ms", "Encryption"), ("decrypt_median_ms", "Decryption")]
    width = 0.36
    for ax, label in zip(axes, BENCH_SIZES):
        subset = {r["cipher"]: r for r in rows if r["size_label"] == label}
        ymax = max(r[k] for r in subset.values() for k, _ in ops)
        for j, cipher in enumerate(COLORS):
            xs = [i + (j - 0.5) * (width + 0.03) for i in range(len(ops))]
            vals = [subset[cipher][k] for k, _ in ops]
            ax.bar(xs, vals, width=width, color=COLORS[cipher], label=cipher, zorder=3)
            for x, v in zip(xs, vals):
                ax.text(x, v + ymax * 0.015, f"{v:.3f}", ha="center", va="bottom", fontsize=7.5, color=MUTED)
        ax.set_title(f"{label} file", fontsize=10.5, color=TEXT)
        ax.set_xticks(range(len(ops)), [name for _, name in ops], fontsize=9, color=TEXT)
        ax.set_ylim(0, ymax * 1.15)
        ax.tick_params(axis="y", labelsize=8, colors=MUTED, length=0)
        ax.tick_params(axis="x", length=0)
        ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
    axes[0].set_ylabel("Median time per file (ms)", fontsize=9, color=MUTED)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper right", ncol=2, frameon=False, fontsize=9)
    fig.suptitle("AES-128-CBC vs 3-DES-CBC: median encryption and decryption time (lower is faster)",
                 x=0.01, ha="left", fontsize=11, color=TEXT)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(path, facecolor="white")
    return path


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        bench_dir: Path | None = None, repeats: int = DEFAULT_REPEATS) -> TaskResult:
    """``input_path`` is accepted for a uniform interface but intentionally not used."""
    if repeats < 2:
        raise ValueError("repeats must be at least 2")
    out_dir = task_output_dir(TASK_ID, output_root)
    files = generate_benchmark_files(bench_dir or BENCHMARKS_DIR)
    rows = benchmark(files, repeats)
    ratio = speedups(rows)

    csv_path = out_dir / "benchmark_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    environment = {
        "python": platform.python_version(),
        "pycryptodome": Crypto.__version__,
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
    }
    json_path = out_dir / "benchmark_results.json"
    json_path.write_text(json.dumps({"environment": environment, "seed": BENCH_SEED,
                                     "rows": rows, "aes_speedup_x": ratio}, indent=2), encoding="utf-8")
    chart = plot_chart(rows, out_dir / "benchmark_chart.png")
    table = format_table(rows)
    (out_dir / "benchmark_table.txt").write_text(table + "\n", encoding="utf-8")

    all_ok = all(r["roundtrip_ok"] for r in rows)
    result = TaskResult(TASK_ID, TITLE, status=Status.COMPLETED if all_ok else Status.FAIL)
    if not all_ok:
        result.reason = "A benchmark decryption did not reproduce its input."
    result.add("Input", "Generated benchmark files (selected file not used, for reproducibility)")
    for label, p in files.items():
        result.add(f"  {label}", f"{p.name}, SHA-256 {sha256_bytes(p.read_bytes())[:16]}...")
    result.add("Repetitions", f"{repeats} timed runs per operation (+{WARMUP} warm-up), median reported")
    for label, r in ratio.items():
        result.add(f"AES speed-up @ {label}", f"encrypt {r['encrypt']}x, decrypt {r['decrypt']}x faster than 3-DES")
    result.add("Round trips", "all PASS" if all_ok else "FAILURE")
    result.details = (
        table + "\n\n"
        f"Environment: Python {environment['python']}, PyCryptodome {environment['pycryptodome']}, "
        f"{environment['platform']}\n"
        "AES is faster for three reasons. It is a single cipher with 10 rounds on 128-bit\n"
        "blocks, while 3-DES runs DES three times (48 rounds) on 64-bit blocks. AES is also\n"
        "accelerated by the CPU (AES-NI) where available. For 1 KB files the fixed cost of\n"
        "creating the cipher objects dominates, so the gap is smaller there. Absolute times\n"
        "depend on the machine; the AES : 3-DES ratio is the meaningful result."
    )
    result.data = {"rows": rows, "speedup": ratio, "environment": environment}
    result.artifacts += [*files.values(), csv_path, json_path, out_dir / "benchmark_table.txt", chart]
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0], takes_file=False)
