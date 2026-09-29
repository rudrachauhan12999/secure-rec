"""Integrated secure pipeline: sender -> package -> receiver."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import certificates as certs
from core.config import PROJECT_ROOT
from core.file_handler import describe_file
from core.results import Status
from pipeline import receiver as rx
from pipeline import secure_pipeline as sp
from pipeline.package import PackageFormatError, TransferPackage, certificate_fingerprint
from pipeline.sender import build_manifest, create_sender_identity, seal_package


@pytest.fixture(autouse=True)
def _require_openssl():
    try:
        certs.find_openssl()
    except certs.OpenSSLNotFound:
        pytest.skip("OpenSSL not installed")


@pytest.fixture
def keys_dir(tmp_path):
    return tmp_path / "keys"


def run_pipeline(src, out_root, keys_dir, rsa_identities, tamper=None):
    return sp.run(src, output_root=out_root, keys_dir=keys_dir, tamper=tamper,
                  sender_key=rsa_identities["sender"], receiver_key=rsa_identities["receiver"],
                  attacker_key=rsa_identities["attacker"])


# ------------------------------------------------------------- successful runs
@pytest.mark.parametrize("fixture", ["sample_file", "binary_file", "pdf_like_file", "png_image", "jpeg_image"])
def test_round_trip_any_file(fixture, request, out_root, keys_dir, rsa_identities):
    src = request.getfixturevalue(fixture)
    result = run_pipeline(src, out_root, keys_dir, rsa_identities)
    assert result.status is Status.PASS, result.reason
    d = result.data
    assert d["accepted"] and d["byte_match"] and d["failed_stage"] is None
    assert d["final_result"] == "SECURE TRANSFER SUCCESSFUL"
    recovered = out_root / sp.TASK_ID / "receiver" / f"recovered_{src.name}"
    assert recovered.read_bytes() == src.read_bytes()                       # exact byte recovery
    assert [s["stage"] for s in d["stages"]] == rx.RECEIVER_STAGES + [sp.STAGE_BYTES]
    assert all(s["ok"] for s in d["stages"])


def test_report_has_required_sections(sample_file, out_root, keys_dir, rsa_identities):
    run_pipeline(sample_file, out_root, keys_dir, rsa_identities)
    text = (out_root / sp.TASK_ID / "report.txt").read_text()
    for needle in ("INPUT", "Original SHA-256", "SECURITY", "AES encryption              : PASS",
                   "RSA key protection          : PASS", "Certificate verification    : PASS",
                   "Digital signature           : VALID", "SHA-256 integrity           : VERIFIED",
                   "RECOVERY", "Byte-for-byte match         : TRUE", "SECURE TRANSFER SUCCESSFUL",
                   "NO real-world CA trust"):
        assert needle in text, needle
    signed = json.loads((out_root / sp.TASK_ID / "sender" / "signed_structure.json").read_text())
    assert set(signed) == {"format", "header", "sender_certificate_sha256", "wrapped_key_sha256", "manifest_iv",
                           "manifest_ciphertext_sha256", "payload_iv", "payload_ciphertext_sha256"}


def test_empty_file_rejected_by_validation_policy(tmp_path, out_root, keys_dir, rsa_identities):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    result = run_pipeline(empty, out_root, keys_dir, rsa_identities)
    assert result.status is Status.ERROR and "empty" in result.reason


def test_repeated_runs_use_fresh_keys(sample_file, tmp_path):
    r1 = sp.run(sample_file, output_root=tmp_path / "o1", keys_dir=tmp_path / "k1")
    r2 = sp.run(sample_file, output_root=tmp_path / "o2", keys_dir=tmp_path / "k2")
    assert r1.status is r2.status is Status.PASS
    for field in ("session_key_fingerprint", "receiver_key_fingerprint", "sender_certificate_sha256"):
        assert r1.data[field] != r2.data[field]
    p1 = (tmp_path / "o1" / sp.TASK_ID / "sender" / sp.PACKAGE_NAME).read_bytes()
    p2 = (tmp_path / "o2" / sp.TASK_ID / "sender" / sp.PACKAGE_NAME).read_bytes()
    assert TransferPackage.from_bytes(p1).payload_ciphertext != TransferPackage.from_bytes(p2).payload_ciphertext


# ----------------------------------------------------------------- tampering
@pytest.mark.parametrize("target, stage", [
    ("ciphertext", rx.STAGE_SIGNATURE),
    ("wrapped-key", rx.STAGE_SIGNATURE),
    ("signature", rx.STAGE_SIGNATURE),
    ("certificate", rx.STAGE_CERT),
    ("impersonation", rx.STAGE_IDENTITY),
])
def test_tamper_mode_detects_and_names_failed_stage(target, stage, binary_file, out_root, keys_dir, rsa_identities):
    result = run_pipeline(binary_file, out_root, keys_dir, rsa_identities, tamper=target)
    assert result.status is Status.PASS, result.reason          # PASS = tampering was detected as expected
    d = result.data
    assert not d["accepted"] and d["failed_stage"] == stage and d["byte_match"] is None
    assert d["final_result"].startswith("TAMPERING DETECTED")
    out = out_root / sp.TASK_ID
    assert not (out / "receiver" / f"recovered_{binary_file.name}").exists()   # nothing accepted/repaired
    tampered = (out / "tamper" / f"tampered_{sp.PACKAGE_NAME}").read_bytes()
    genuine = (out / "sender" / sp.PACKAGE_NAME).read_bytes()
    assert tampered != genuine
    later = [s for s in rx.RECEIVER_STAGES[rx.RECEIVER_STAGES.index(stage) + 1:]]
    assert not any(s["stage"] in later for s in d["stages"])       # processing stopped


def test_tampering_is_not_default(sample_file, out_root, keys_dir, rsa_identities):
    result = run_pipeline(sample_file, out_root, keys_dir, rsa_identities)
    assert result.data["mode"] == "normal" and not (out_root / sp.TASK_ID / "tamper").exists()


def test_unknown_tamper_target(sample_file, out_root, keys_dir, rsa_identities):
    assert run_pipeline(sample_file, out_root, keys_dir, rsa_identities, tamper="nonsense").status is Status.ERROR


# ------------------------------------------------------- receiver API level
@pytest.fixture
def sealed(tmp_path, binary_file, rsa_identities):
    """A genuine package, its trust store and the original bytes."""
    identity = create_sender_identity(tmp_path / "k", tmp_path / "c", rsa_identities["sender"])
    trust = rx.TrustStore("SECURE-REC Sender", certificate_fingerprint(identity.certificate_pem))
    data = binary_file.read_bytes()
    manifest = build_manifest(describe_file(binary_file), data)
    package, _ = seal_package(data, manifest, identity, rsa_identities["receiver"].publickey())
    return package, trust, data, identity, manifest


def test_receiver_accepts_genuine_package(sealed, rsa_identities, tmp_path):
    package, trust, data, *_ = sealed
    outcome = rx.receive_package(package.to_bytes(), rsa_identities["receiver"], trust, tmp_path / "w")
    assert outcome.accepted and outcome.recovered == data


def test_modified_package_fields_rejected(sealed, rsa_identities, tmp_path):
    package, trust, *_ = sealed
    doc = json.loads(package.to_bytes())
    doc["header"]["sender"] = "Someone Else"                               # edit unencrypted metadata
    outcome = rx.receive_package(json.dumps(doc).encode(), rsa_identities["receiver"], trust, tmp_path / "w")
    assert outcome.failed_stage == rx.STAGE_SIGNATURE

    for broken in (package.to_bytes()[:-50], b"not a package", b"{}", b"\xff\xfe"):
        outcome = rx.receive_package(broken, rsa_identities["receiver"], trust, tmp_path / "w")
        assert outcome.failed_stage == rx.STAGE_FORMAT and not outcome.accepted


def test_wrong_rsa_private_key(sealed, rsa_identities, tmp_path):
    package, trust, *_ = sealed
    outcome = rx.receive_package(package.to_bytes(), rsa_identities["attacker"], trust, tmp_path / "w")
    assert outcome.failed_stage == rx.STAGE_KEY and outcome.recovered is None


def test_untrusted_certificate(sealed, rsa_identities, tmp_path):
    package, _, *_ = sealed
    other_trust = rx.TrustStore("SECURE-REC Sender", "0" * 64)
    outcome = rx.receive_package(package.to_bytes(), rsa_identities["receiver"], other_trust, tmp_path / "w")
    assert outcome.failed_stage == rx.STAGE_IDENTITY


def test_recovered_sha256_mismatch(sealed, rsa_identities, tmp_path):
    """Sender signs a manifest whose reference hash is wrong -> integrity stage must fail."""
    _, trust, data, identity, manifest = sealed
    bad_manifest = dict(manifest, sha256="00" * 32)
    package, _ = seal_package(data, bad_manifest, identity, rsa_identities["receiver"].publickey())
    outcome = rx.receive_package(package.to_bytes(), rsa_identities["receiver"], trust, tmp_path / "w")
    assert outcome.failed_stage == rx.STAGE_INTEGRITY and not outcome.accepted
    assert outcome.stage(rx.STAGE_DECRYPT).ok                        # decryption itself worked


def test_package_serialization_round_trip(sealed):
    package = sealed[0]
    again = TransferPackage.from_bytes(package.to_bytes())
    assert again == package and again.signed_bytes() == package.signed_bytes()
    with pytest.raises(PackageFormatError):
        TransferPackage.from_bytes(json.dumps({"format": "OTHER/9"}).encode())


# ------------------------------------------------------------------ secrets
def test_no_private_keys_or_session_keys_in_outputs(binary_file, out_root, keys_dir, rsa_identities, monkeypatch):
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    monkeypatch.setattr("core.hybrid.generate_aes_key", lambda bits=128: session_key)
    import base64
    for tamper in (None, "impersonation"):
        run_pipeline(binary_file, out_root, keys_dir, rsa_identities, tamper=tamper)
        markers = [b"PRIVATE KEY", session_key, session_key.hex().encode(), base64.b64encode(session_key)]
        for key in rsa_identities.values():
            markers.append("".join(key.export_key().decode().splitlines()[1:-1])[:48].encode())
            markers.append(format(key.d, "x")[:48].encode())
        files = [f for f in (out_root / sp.TASK_ID).rglob("*") if f.is_file()]
        assert files
        for f in files:
            content = f.read_bytes()
            for m in markers:
                assert m not in content, f"secret material in {f}"
    assert (keys_dir / "receiver_private_key.pem").exists() and (keys_dir / "sender_private_key.pem").exists()


def test_plaintext_not_in_transmitted_package(sample_file, out_root, keys_dir, rsa_identities):
    run_pipeline(sample_file, out_root, keys_dir, rsa_identities)
    blob = (out_root / sp.TASK_ID / "sender" / sp.PACKAGE_NAME).read_bytes()
    data = sample_file.read_bytes()
    for i in range(0, len(data) - 32, 4096):
        assert data[i:i + 32] not in blob
    assert b"student_records" not in blob                               # file name travels encrypted


def test_pipeline_code_has_no_gui_dependency():
    for f in (PROJECT_ROOT / "pipeline").glob("*.py"):
        assert "tkinter" not in f.read_text().lower(), f
