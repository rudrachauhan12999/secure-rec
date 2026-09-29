"""Task 3: ECB vs CBC on images."""

from __future__ import annotations

import pytest
from PIL import Image

from core.results import Status
from tasks import task03_ecb_cbc as t3


def test_non_image_is_not_applicable(sample_file, binary_file, out_root):
    for src in (sample_file, binary_file):
        result = t3.run(src, output_root=out_root)
        assert result.status is Status.NOT_APPLICABLE
        assert result.reason == "Image input required"


def test_ecb_leaks_patterns_cbc_does_not(png_image, out_root):
    result = t3.run(png_image, output_root=out_root)
    assert result.status is Status.PASS, result.reason
    stats = result.data["block_stats"]
    assert stats["plaintext"]["repeated_percent"] > 50
    # ECB maps equal blocks to equal blocks, so the repetition structure is preserved exactly
    # (ECB/CBC have one extra all-padding block at the end).
    assert stats["ecb"]["unique_blocks"] in (stats["plaintext"]["unique_blocks"],
                                            stats["plaintext"]["unique_blocks"] + 1)
    assert stats["cbc"]["blocks_in_repeated_groups"] == 0


@pytest.mark.parametrize("fixture", ["png_image", "jpeg_image", "rgba_image"])
def test_outputs_are_viewable_and_keep_dimensions(fixture, request, out_root):
    src = request.getfixturevalue(fixture)
    result = t3.run(src, output_root=out_root)
    assert result.status is Status.PASS, result.reason
    with Image.open(src) as original:
        size = original.size
    for key in ("original", "ecb", "cbc"):
        with Image.open(result.data["images"][key]) as img:
            assert img.size == size and img.format == "PNG"
    assert (out_root / "task03" / "comparison_original_ecb_cbc.png").exists()


def test_demo_image_mode(out_root):
    result = t3.run(None, output_root=out_root, use_demo_image=True)
    assert result.status is Status.PASS
    assert result.data["block_stats"]["ecb"]["repeated_percent"] > 90
