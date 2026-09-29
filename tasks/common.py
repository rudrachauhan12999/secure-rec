"""Helpers shared by the individual task modules."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable

from core.config import DEFAULT_SAMPLE_FILE
from core.results import TaskResult


def resolve_input(input_path: str | Path | None) -> Path:
    """Use the selected file, or fall back to the bundled student dataset."""
    return Path(input_path) if input_path else DEFAULT_SAMPLE_FILE


def cli_main(run: Callable[..., TaskResult], description: str, takes_file: bool = True) -> None:
    """Minimal command-line entry point so each task runs on its own:

        python -m tasks.task01_symmetric [path/to/file]
    """
    parser = argparse.ArgumentParser(description=description)
    if takes_file:
        parser.add_argument("file", nargs="?", help="input file (default: data/student_records.txt)")
    parser.add_argument("--out", help="output root directory (default: outputs/)")
    args = parser.parse_args()

    kwargs = {"output_root": Path(args.out) if args.out else None}
    if takes_file:
        kwargs["input_path"] = args.file
    result = run(**kwargs)
    print(result.to_text())
    sys.exit(0 if result.ok else 1)
