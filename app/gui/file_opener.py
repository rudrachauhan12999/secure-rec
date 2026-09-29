"""Open generated files/folders with the operating system's default application.

Only paths inside the allowed output roots can be opened, so a crafted
artifact path cannot make the GUI launch arbitrary files, and nothing under
keys/ is ever opened.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable


class UnsafePathError(ValueError):
    pass


def check_allowed(path: Path, allowed_roots: Iterable[Path]) -> Path:
    resolved = Path(path).resolve()
    for root in allowed_roots:
        try:
            resolved.relative_to(Path(root).resolve())
            break
        except ValueError:
            continue
    else:
        raise UnsafePathError(f"Refusing to open a path outside the output folders: {path}")
    if not resolved.exists():
        raise FileNotFoundError(f"Not found: {resolved}")
    return resolved


def system_open(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def open_path(path: Path, allowed_roots: Iterable[Path], launcher: Callable[[Path], None] = system_open) -> Path:
    resolved = check_allowed(path, allowed_roots)
    launcher(resolved)
    return resolved
