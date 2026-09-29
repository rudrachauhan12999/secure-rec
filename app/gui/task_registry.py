"""Adapter between the GUI and the existing backend (no Tkinter, no crypto).

Every button maps to an existing ``run()`` function in ``tasks/`` or
``pipeline/``.  This module only decides which arguments to pass - it never
performs cryptographic work itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.file_handler import describe_file
from core.hashing import sha256_file
from core.results import Status, TaskResult
from pipeline import secure_pipeline
from tasks import (task01_symmetric, task02_avalanche, task03_ecb_cbc, task04_performance, task05_hybrid,
                   task06_diffie_hellman, task07_mitm, task08_sha256, task09_tampering, task10_signature,
                   task11_certificate, task12_kerberos)

FILE, IMAGE, NONE, BENCHMARK = "file", "image", "none", "benchmark"
PIPELINE_KEY = secure_pipeline.TASK_ID


@dataclass(frozen=True)
class TaskSpec:
    key: str                              # output folder name, e.g. "task01"
    number: str
    label: str                            # short button text
    title: str                            # the task module's own TITLE
    func: Callable[..., TaskResult]       # the existing run() function
    input_kind: str                       # FILE | IMAGE | NONE | BENCHMARK
    accepts_keys_dir: bool = False        # task writes a private key to keys/<key>/


TASKS: tuple[TaskSpec, ...] = (
    TaskSpec("task01", "01", "AES / 3-DES", task01_symmetric.TITLE, task01_symmetric.run, FILE),
    TaskSpec("task02", "02", "Avalanche Effect", task02_avalanche.TITLE, task02_avalanche.run, FILE),
    TaskSpec("task03", "03", "ECB vs CBC", task03_ecb_cbc.TITLE, task03_ecb_cbc.run, IMAGE),
    TaskSpec("task04", "04", "Performance", task04_performance.TITLE, task04_performance.run, BENCHMARK),
    TaskSpec("task05", "05", "RSA + AES", task05_hybrid.TITLE, task05_hybrid.run, FILE),
    TaskSpec("task06", "06", "Diffie-Hellman", task06_diffie_hellman.TITLE, task06_diffie_hellman.run, NONE),
    TaskSpec("task07", "07", "MITM Attack", task07_mitm.TITLE, task07_mitm.run, FILE),
    TaskSpec("task08", "08", "SHA-256", task08_sha256.TITLE, task08_sha256.run, FILE),
    TaskSpec("task09", "09", "Tampering", task09_tampering.TITLE, task09_tampering.run, FILE),
    TaskSpec("task10", "10", "Digital Signature", task10_signature.TITLE, task10_signature.run, FILE),
    TaskSpec("task11", "11", "Certificate", task11_certificate.TITLE, task11_certificate.run, FILE,
             accepts_keys_dir=True),
    TaskSpec("task12", "12", "Kerberos", task12_kerberos.TITLE, task12_kerberos.run, NONE),
)
TASK_BY_KEY = {spec.key: spec for spec in TASKS}

INPUT_HINTS = {
    FILE: "uses the selected file",
    IMAGE: "requires an image file",
    NONE: "no file needed",
    BENCHMARK: "uses generated 1/10/100 KB benchmark files",
}


@dataclass(frozen=True)
class FileSummary:
    path: Path
    name: str
    type_label: str
    size_bytes: int
    human_size: str
    sha256: str
    is_image: bool


def inspect_file(path: str | Path) -> FileSummary:
    """Validate a selection and gather what the file panel shows.

    Raises ``core.validators.InputValidationError`` for missing/empty/oversized files.
    """
    info = describe_file(path)
    return FileSummary(info.path, info.name, info.type_label, info.size_bytes, info.human_size,
                       sha256_file(info.path), info.is_image)


def no_file_result(task_id: str, title: str) -> TaskResult:
    return TaskResult(task_id, title, status=Status.ERROR,
                      reason="No file selected. Use 'Select File...' or 'Use Sample Dataset' first.")


def run_task(key: str, selected: Path | None, output_root: Path | None = None,
             keys_root: Path | None = None, **overrides) -> TaskResult:
    """Invoke the existing task implementation for ``key``."""
    spec = TASK_BY_KEY[key]
    kwargs: dict = {"output_root": output_root, **overrides}
    if spec.input_kind in (FILE, IMAGE):
        if selected is None:
            return no_file_result(spec.key, spec.title)
        kwargs["input_path"] = selected
    if spec.accepts_keys_dir and keys_root is not None:
        kwargs["keys_dir"] = keys_root / spec.key
    return spec.func(**kwargs)


def run_pipeline(selected: Path | None, tamper: bool = False, output_root: Path | None = None,
                 keys_root: Path | None = None, **overrides) -> TaskResult:
    """Invoke pipeline.secure_pipeline.run(); tamper mode uses its default target (ciphertext)."""
    if selected is None:
        return no_file_result(PIPELINE_KEY, secure_pipeline.TITLE)
    return secure_pipeline.run(selected, output_root=output_root,
                               keys_dir=keys_root / PIPELINE_KEY if keys_root is not None else None,
                               tamper="ciphertext" if tamper else None, **overrides)
