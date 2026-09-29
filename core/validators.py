"""Input validation used before any task touches a user-selected file."""

from __future__ import annotations

from pathlib import Path

from core.config import MAX_INPUT_BYTES


class InputValidationError(ValueError):
    """Raised when a selected file cannot be processed."""


def validate_input_file(path: str | Path, max_bytes: int = MAX_INPUT_BYTES) -> Path:
    """Return a resolved ``Path`` if the file is usable, otherwise raise.

    Any file type is accepted: the ciphers operate on raw bytes, so text,
    PDF, image and arbitrary binary files are all handled identically.
    """
    if path is None or str(path).strip() == "":
        raise InputValidationError("No file selected.")
    p = Path(path).expanduser()
    if not p.exists():
        raise InputValidationError(f"File not found: {p}")
    if not p.is_file():
        raise InputValidationError(f"Not a regular file: {p}")
    size = p.stat().st_size
    if size == 0:
        raise InputValidationError(f"File is empty: {p.name}")
    if size > max_bytes:
        raise InputValidationError(
            f"File is too large ({size} bytes); limit is {max_bytes} bytes."
        )
    return p.resolve()


def is_image_file(path: str | Path) -> bool:
    """True if Pillow can identify the file as a raster image.

    Content is checked, not just the extension, so a renamed .txt file is not
    mistaken for an image.
    """
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(path) as img:
            img.verify()
        return True
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        return False
