"""File I/O helpers: reading arbitrary files as bytes and organising outputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.config import OUTPUT_DIR
from core.validators import is_image_file, validate_input_file


@dataclass(frozen=True)
class FileInfo:
    path: Path
    name: str
    extension: str      # e.g. ".txt" ('' if none)
    type_label: str     # e.g. "TXT", "PNG", "BINARY"
    size_bytes: int
    is_image: bool

    @property
    def human_size(self) -> str:
        return human_readable_size(self.size_bytes)


def human_readable_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"  # unreachable


def describe_file(path: str | Path) -> FileInfo:
    p = validate_input_file(path)
    ext = p.suffix.lower()
    return FileInfo(
        path=p,
        name=p.name,
        extension=ext,
        type_label=ext.lstrip(".").upper() or "BINARY",
        size_bytes=p.stat().st_size,
        is_image=is_image_file(p),
    )


def read_file_bytes(path: str | Path) -> bytes:
    """Read the whole file as raw bytes (after validation)."""
    return validate_input_file(path).read_bytes()


def write_file_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def task_output_dir(task_id: str, output_root: Path | None = None) -> Path:
    """Return (and create) e.g. ``outputs/task01``."""
    out = (output_root or OUTPUT_DIR) / task_id
    out.mkdir(parents=True, exist_ok=True)
    return out
