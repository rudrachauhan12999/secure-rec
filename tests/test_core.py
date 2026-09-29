"""Tests for the shared core utilities used by Tasks 1-4."""

from __future__ import annotations

import pytest
from Crypto.Cipher import AES

from core import crypto_utils as cu
from core.file_handler import describe_file, human_readable_size
from core.hashing import sha256_bytes, sha256_file
from core.key_manager import generate_3des_key, generate_aes_key, generate_iv, key_fingerprint
from core.validators import InputValidationError, is_image_file, validate_input_file

LENGTHS = [0, 1, 7, 8, 15, 16, 17, 1000, 4096]


@pytest.mark.parametrize("n", LENGTHS)
def test_aes_cbc_round_trip(n):
    key, data = generate_aes_key(), bytes(range(256)) * (n // 256 + 1)
    data = data[:n]
    iv, ct = cu.aes_cbc_encrypt(data, key)
    assert len(iv) == 16 and len(ct) % 16 == 0 and len(ct) > len(data)
    assert cu.aes_cbc_decrypt(ct, key, iv) == data


@pytest.mark.parametrize("n", LENGTHS)
def test_3des_cbc_round_trip(n):
    key, data = generate_3des_key(), (b"\x00\xff" * 3000)[:n]
    iv, ct = cu.tdes_cbc_encrypt(data, key)
    assert len(key) == 24 and len(iv) == 8 and len(ct) % 8 == 0
    assert cu.tdes_cbc_decrypt(ct, key, iv) == data


def test_aes_ecb_round_trip_and_block_repetition():
    key = generate_aes_key()
    data = b"A" * 16 * 4
    ct = cu.aes_ecb_encrypt(data, key)
    assert cu.aes_ecb_decrypt(ct, key) == data
    assert len({ct[i:i + 16] for i in range(0, 64, 16)}) == 1  # ECB: equal blocks leak


def test_fresh_iv_gives_different_ciphertext():
    key, data = generate_aes_key(), b"same message"
    (iv1, c1), (iv2, c2) = cu.aes_cbc_encrypt(data, key), cu.aes_cbc_encrypt(data, key)
    assert iv1 != iv2 and c1 != c2


def test_wrong_key_does_not_recover_plaintext():
    data = b"confidential student grades" * 10
    iv, ct = cu.aes_cbc_encrypt(data, generate_aes_key())
    try:
        assert cu.aes_cbc_decrypt(ct, generate_aes_key(), iv) != data
    except ValueError:
        pass  # padding check usually fails - also acceptable


def test_iv_container_pack_unpack():
    iv, ct = generate_iv(16), b"\x01" * 32
    assert cu.unpack_iv_ciphertext(cu.pack_iv_ciphertext(iv, ct), 16) == (iv, ct)
    with pytest.raises(ValueError):
        cu.unpack_iv_ciphertext(b"\x00" * 20, 16)


def test_key_generation_properties():
    assert len(generate_aes_key(128)) == 16
    assert len(generate_aes_key(256)) == 32
    with pytest.raises(ValueError):
        generate_aes_key(100)
    assert generate_aes_key() != generate_aes_key()
    fp = key_fingerprint(b"k" * 16)
    assert len(fp) == 16 and b"k".hex() * 16 not in fp


def test_single_block_requires_16_bytes():
    with pytest.raises(ValueError):
        cu.aes_encrypt_single_block(b"short", generate_aes_key())
    assert len(cu.aes_encrypt_single_block(b"\x00" * AES.block_size, generate_aes_key())) == 16


def test_flip_bit_and_hamming_distance():
    data = b"\x00\x00"
    assert cu.flip_bit(data, 0) == b"\x80\x00"
    assert cu.flip_bit(data, 15) == b"\x00\x01"
    assert cu.count_differing_bits(data, cu.flip_bit(data, 9)) == 1
    assert cu.count_differing_bits(b"\x00", b"\xff") == 8
    with pytest.raises(IndexError):
        cu.flip_bit(data, 16)
    with pytest.raises(ValueError):
        cu.count_differing_bits(b"a", b"ab")


def test_sha256_consistency(sample_file):
    data = sample_file.read_bytes()
    assert sha256_bytes(data) == sha256_bytes(data) == sha256_file(sample_file)
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_bytes(data) != sha256_bytes(cu.flip_bit(data, 0))


def test_validators(tmp_path, sample_file, png_image):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    for bad in (None, "", tmp_path / "missing.txt", tmp_path, empty):
        with pytest.raises(InputValidationError):
            validate_input_file(bad)
    too_big = tmp_path / "big.bin"
    too_big.write_bytes(b"x" * 11)
    with pytest.raises(InputValidationError):
        validate_input_file(too_big, max_bytes=10)
    fake_png = tmp_path / "not_really.png"
    fake_png.write_bytes(sample_file.read_bytes()[:200])
    assert is_image_file(png_image) and not is_image_file(sample_file) and not is_image_file(fake_png)


def test_describe_file(sample_file, binary_file):
    info = describe_file(sample_file)
    assert (info.name, info.type_label, info.size_bytes, info.is_image) == (
        "student_records.txt", "TXT", sample_file.stat().st_size, False)
    assert describe_file(binary_file).type_label == "BIN"
    assert human_readable_size(512) == "512 B" and human_readable_size(12_700) == "12.4 KB"
