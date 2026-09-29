"""Shared pytest fixtures.

All task outputs are redirected to pytest's temporary directory so running
the tests never touches the real ``outputs/`` folder.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import DEFAULT_SAMPLE_FILE  # noqa: E402
from tasks.task03_ecb_cbc import generate_demo_image  # noqa: E402


@pytest.fixture
def out_root(tmp_path: Path) -> Path:
    return tmp_path / "outputs"


@pytest.fixture
def sample_file() -> Path:
    assert DEFAULT_SAMPLE_FILE.exists(), "bundled dataset data/student_records.txt is missing"
    return DEFAULT_SAMPLE_FILE


@pytest.fixture
def binary_file(tmp_path: Path) -> Path:
    """Random bytes incl. NULs and every byte value - not valid text."""
    p = tmp_path / "random_payload.bin"
    p.write_bytes(bytes(range(256)) * 4 + os.urandom(5000 + 7))  # deliberately not block aligned
    return p


@pytest.fixture
def pdf_like_file(tmp_path: Path) -> Path:
    p = tmp_path / "document.pdf"
    p.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + os.urandom(3000) + b"\n%%EOF\n")
    return p


@pytest.fixture
def png_image(tmp_path: Path) -> Path:
    return generate_demo_image(tmp_path / "logo.png", size=128)


@pytest.fixture
def jpeg_image(tmp_path: Path) -> Path:
    p = tmp_path / "photo.jpg"
    Image.new("RGB", (97, 61), (200, 30, 30)).save(p, format="JPEG")  # odd size -> padding path
    return p


@pytest.fixture
def rgba_image(tmp_path: Path) -> Path:
    p = tmp_path / "transparent.png"
    Image.new("RGBA", (40, 40), (0, 0, 255, 128)).save(p, format="PNG")
    return p


@pytest.fixture(scope="session")
def rsa_identities():
    """RSA-2048 keys generated once per test session (generation is slow)."""
    from core.key_manager import generate_rsa_keypair

    return {role: generate_rsa_keypair() for role in ("sender", "receiver", "attacker")}


@pytest.fixture(scope="session")
def rsa_key(rsa_identities):
    return rsa_identities["receiver"]
