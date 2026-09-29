"""Central project paths.

Every module resolves locations through this file so that tasks, the pipeline,
the GUI and the tests all agree on where inputs and generated evidence live.
Paths are absolute (anchored at the project root), so the application works
no matter which directory it is launched from.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

DATA_DIR: Path = PROJECT_ROOT / "data"
# Default sample input: Kaggle "Student Performance Data Set" (student-mat),
# https://www.kaggle.com/datasets/dskagglemt/student-performance-data-set
DEFAULT_SAMPLE_FILE: Path = DATA_DIR / "student_records.txt"

OUTPUT_DIR: Path = PROJECT_ROOT / "outputs"
KEYS_DIR: Path = PROJECT_ROOT / "keys"
BENCHMARKS_DIR: Path = PROJECT_ROOT / "benchmarks"

# Refuse inputs above this size: every task holds the file in memory.
MAX_INPUT_BYTES: int = 200 * 1024 * 1024
