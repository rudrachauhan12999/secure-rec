"""Task 3 - ECB vs CBC pattern leakage on an image.

ECB encrypts each 16-byte block independently, so equal plaintext blocks
(e.g. runs of identical background pixels) become equal ciphertext blocks and
the picture's outline remains visible.  CBC XORs each block with the previous
ciphertext block (and the first with a random IV) before encryption, so
repeated plaintext blocks produce unrelated ciphertext and the output looks
like noise.

Header / padding handling
-------------------------
Encrypting the whole image *file* would also scramble its header (PNG/JPEG
structure) and the result could not be displayed.  Therefore:

* the image is decoded with Pillow and converted to 24-bit RGB (alpha and
  palettes are dropped/expanded) - the width and height act as the "header"
  and are kept in clear;
* only the raw pixel bytes are encrypted (PKCS#7 padded to 16 bytes);
* for viewing, the first ``width*height*3`` ciphertext bytes are reinterpreted
  as RGB pixels (the extra padding bytes don't fit into the image);
* the full ciphertexts are saved separately and decrypted to prove correctness;
* outputs are written as PNG (lossless) - JPEG recompression would alter the
  ciphertext bytes.

Leakage is strongest for images with large flat areas (logos, diagrams); a
noisy photograph has few repeated blocks, so ECB looks less revealing there.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw

from core import crypto_utils as cu
from core.file_handler import describe_file, task_output_dir, write_file_bytes
from core.key_manager import generate_aes_key, key_fingerprint
from core.results import Status, TaskResult, guarded
from tasks.common import resolve_input

TASK_ID = "task03"
TITLE = "Task 3 - ECB vs CBC Pattern Leakage (AES-128)"
PREVIEW_HEIGHT = 320


def generate_demo_image(path: Path, size: int = 256) -> Path:
    """Draw a flat-coloured test picture (large uniform regions show ECB leakage clearly)."""
    img = Image.new("RGB", (size, size), (255, 255, 255))
    d = ImageDraw.Draw(img)
    s = size / 256
    d.rectangle([16 * s, 16 * s, 120 * s, 120 * s], fill=(30, 90, 200))
    d.ellipse([136 * s, 16 * s, 240 * s, 120 * s], fill=(230, 100, 40))
    d.polygon([(128 * s, 140 * s), (40 * s, 240 * s), (216 * s, 240 * s)], fill=(20, 140, 90))
    for x in range(0, size, int(32 * s)):
        d.rectangle([x, 124 * s, x + 16 * s, 134 * s], fill=(0, 0, 0))
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG")
    return path


def block_stats(data: bytes, block: int = cu.AES_BLOCK) -> dict:
    """Count how many 16-byte blocks repeat - repeated blocks = leaked structure."""
    blocks = [data[i:i + block] for i in range(0, len(data) - len(data) % block, block)]
    counts = Counter(blocks)
    repeated = sum(c for c in counts.values() if c > 1)
    return {
        "total_blocks": len(blocks),
        "unique_blocks": len(counts),
        "blocks_in_repeated_groups": repeated,
        "repeated_percent": round(100 * repeated / len(blocks), 2) if blocks else 0.0,
    }


def _as_image(data: bytes, size: tuple[int, int]) -> Image.Image:
    return Image.frombytes("RGB", size, data[: size[0] * size[1] * 3])


def build_comparison(images: list[tuple[str, Image.Image]], path: Path) -> Path:
    """Side-by-side 'Original | ECB | CBC' figure for the GUI and the report."""
    w0, h0 = images[0][1].size
    scale = PREVIEW_HEIGHT / h0
    tw, th = max(1, round(w0 * scale)), PREVIEW_HEIGHT
    pad, label_h = 12, 28
    sheet = Image.new("RGB", (pad + len(images) * (tw + pad), label_h + th + pad), (255, 255, 255))
    draw = ImageDraw.Draw(sheet)
    for i, (label, img) in enumerate(images):
        x = pad + i * (tw + pad)
        draw.text((x, 8), label, fill=(0, 0, 0))
        sheet.paste(img.resize((tw, th), Image.NEAREST), (x, label_h))
    sheet.save(path, format="PNG")
    return path


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        use_demo_image: bool = False) -> TaskResult:
    out_dir = task_output_dir(TASK_ID, output_root)
    if use_demo_image:
        input_path = generate_demo_image(out_dir / "demo_input.png")
    info = describe_file(resolve_input(input_path))

    result = TaskResult(TASK_ID, TITLE)
    result.add("Input file", f"{info.name} ({info.type_label}, {info.human_size})")
    if not info.is_image:
        result.status = Status.NOT_APPLICABLE
        result.reason = "Image input required"
        result.details = ("Select an image file (PNG, JPG, BMP, ...) to run this demonstration, "
                          "or run with the generated demo image.")
        return result

    with Image.open(info.path) as src:
        original = src.convert("RGB")
    size = original.size
    pixels = original.tobytes()

    key = generate_aes_key(128)
    ecb_ct = cu.aes_ecb_encrypt(pixels, key)
    cbc_iv, cbc_ct = cu.aes_cbc_encrypt(pixels, key)

    # Prove both ciphertexts are real, decryptable encryptions of the pixels.
    ecb_ok = cu.aes_ecb_decrypt(ecb_ct, key) == pixels
    cbc_ok = cu.aes_cbc_decrypt(cbc_ct, key, cbc_iv) == pixels

    ecb_img, cbc_img = _as_image(ecb_ct, size), _as_image(cbc_ct, size)
    paths = {
        "original": out_dir / "original_rgb.png",
        "ecb": out_dir / "encrypted_ecb.png",
        "cbc": out_dir / "encrypted_cbc.png",
    }
    original.save(paths["original"], format="PNG")
    ecb_img.save(paths["ecb"], format="PNG")
    cbc_img.save(paths["cbc"], format="PNG")
    paths["comparison"] = build_comparison(
        [("Original", original), ("AES-ECB", ecb_img), ("AES-CBC", cbc_img)],
        out_dir / "comparison_original_ecb_cbc.png",
    )
    ecb_bin = write_file_bytes(out_dir / "pixels.aes128ecb.bin", ecb_ct)
    cbc_bin = write_file_bytes(out_dir / "pixels.aes128cbc.bin", cu.pack_iv_ciphertext(cbc_iv, cbc_ct))

    stats = {"plaintext": block_stats(pixels), "ecb": block_stats(ecb_ct), "cbc": block_stats(cbc_ct)}

    result.status = Status.PASS if (ecb_ok and cbc_ok) else Status.FAIL
    if result.status is Status.FAIL:
        result.reason = "Decryption check failed."
    result.add("Image", f"{size[0]} x {size[1]} px, RGB, {len(pixels)} pixel bytes")
    result.add("Key", f"AES-128 random, fingerprint {key_fingerprint(key)} (same key for ECB and CBC)")
    result.add("CBC IV", cbc_iv.hex())
    for name, s in stats.items():
        result.add(f"Repeated 16-B blocks ({name.upper()})",
                   f"{s['blocks_in_repeated_groups']}/{s['total_blocks']} ({s['repeated_percent']} %), "
                   f"{s['unique_blocks']} unique")
    result.add("ECB decrypts to original", "PASS" if ecb_ok else "FAIL")
    result.add("CBC decrypts to original", "PASS" if cbc_ok else "FAIL")
    leak = stats["ecb"]["repeated_percent"]
    result.add("Verdict", f"ECB kept {leak} % repeated blocks (visible structure); "
                          f"CBC kept {stats['cbc']['repeated_percent']} %")
    result.artifacts += [*paths.values(), ecb_bin, cbc_bin]
    result.data = {"width": size[0], "height": size[1], "block_stats": stats,
                   "images": {k: str(v) for k, v in paths.items()}}
    result.details = (
        "ECB encrypts equal plaintext blocks to equal ciphertext blocks. The repeated-block\n"
        "count for ECB therefore matches the plaintext exactly, and the outlines stay visible\n"
        "in encrypted_ecb.png. CBC chains each block to the one before it, so the repetition\n"
        "is gone and the image looks like noise.\n"
        "Only the raw RGB pixel bytes were encrypted. The width and height (the 'header') were\n"
        "kept in clear so the ciphertext can be shown as an image. Outputs are lossless PNG.\n"
        + ("\nNote: this image has few repeated blocks (it is probably a photo or has noise).\n"
           "The ECB leakage is easier to see with flat-colour images such as the demo image.\n"
           if stats["plaintext"]["repeated_percent"] < 10 else "")
    )
    result.save(out_dir)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", nargs="?", help="image file to encrypt")
    parser.add_argument("--demo", action="store_true", help="use a generated flat-colour test image")
    parser.add_argument("--out", help="output root directory (default: outputs/)")
    args = parser.parse_args()
    result = run(args.file, Path(args.out) if args.out else None, use_demo_image=args.demo)
    print(result.to_text())
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
