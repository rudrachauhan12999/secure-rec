"""Task 11 - X.509 certificate (OpenSSL).

*** EDUCATIONAL SELF-SIGNED CERTIFICATE - not issued by a trusted CA. ***
Browsers/operating systems would not trust it; here it is trusted only
because the receiver is assumed to have obtained it (or its fingerprint)
through a trusted channel beforehand ("pinning").

Steps
  1. Generate the sender's RSA-2048 key pair (core.key_manager, PyCryptodome).
     The private key is written ONLY to keys/task11/ (git-ignored).
  2. OpenSSL builds and self-signs an X.509 v3 certificate (SHA-256/RSA)
     containing Subject, Issuer, Public Key, Validity period and Signature.
  3. Verification with OpenSSL:
       a. self-signature + validity period  (openssl verify -check_ss_sig)
       b. not expired right now             (openssl x509 -checkend 0)
       c. certificate public key == sender key pair
  4. Negative tests: a certificate with a modified Subject (CN ...Sender ->
     ...Hacker) and one with a modified signature byte must both be rejected;
     the Subject case is also shown as an explicit signature mismatch over the
     signed TBSCertificate bytes (openssl dgst -verify).
  5. Use: the selected file is signed with the sender's private key and
     verified with the public key taken from the certificate.
"""

from __future__ import annotations

from pathlib import Path

from Crypto.PublicKey import RSA

from core import certificates as certs
from core.config import KEYS_DIR
from core.file_handler import describe_file, read_file_bytes, task_output_dir, write_file_bytes
from core.key_manager import generate_rsa_keypair, public_key_fingerprint
from core.results import Status, TaskResult, guarded
from core.signatures import sign_pss, verify_pss
from tasks.common import cli_main, resolve_input

TASK_ID = "task11"
TITLE = "Task 11 - X.509 Certificate (OpenSSL, self-signed, educational)"

SUBJECT = {
    "C": "IN",
    "O": "SECURE-REC Educational Demo",
    "OU": "Information Security Project",
    "CN": "SECURE-REC Sender",
}
VALIDITY_DAYS = 365


def tamper_subject(cert_der: bytes) -> bytes:
    """Replace 'Sender' with 'Hacker' in the Subject CN (same length, so the DER stays well-formed).

    The Subject is the last occurrence (the Issuer comes first). A *different*
    word is used on purpose: X.509 name matching ignores case, so a case-only
    change would still look self-issued rather than demonstrate a bad signature.
    """
    marker = SUBJECT["CN"].encode()
    i = cert_der.rfind(marker)
    if i < 0:
        raise ValueError("subject CN not found in certificate")
    start = i + len(marker) - len(b"Sender")
    return cert_der[:start] + b"Hacker" + cert_der[start + len(b"Sender"):]


def tamper_signature(cert_der: bytes) -> bytes:
    """Flip one byte inside the signature value (the end of the DER encoding)."""
    buf = bytearray(cert_der)
    buf[-5] ^= 0xFF
    return bytes(buf)


@guarded(TASK_ID, TITLE)
def run(input_path: str | Path | None = None, output_root: Path | None = None,
        keys_dir: Path | None = None, sender_key: RSA.RsaKey | None = None) -> TaskResult:
    info = describe_file(resolve_input(input_path))
    out_dir = task_output_dir(TASK_ID, output_root)
    keys_dir = keys_dir or (KEYS_DIR / TASK_ID)
    version = certs.openssl_version()                          # fails early if OpenSSL is missing

    # 1. Key pair (private key -> keys/ only).
    sender_key = sender_key or generate_rsa_keypair()
    key_path = certs.write_private_key(sender_key, keys_dir / "sender_private_key.pem")

    # 2. Certificate.
    cert_pem = certs.create_self_signed_certificate(key_path, out_dir / "sender_certificate.pem",
                                                    SUBJECT, VALIDITY_DAYS)
    cert_der = certs.pem_to_der(cert_pem, out_dir / "sender_certificate.der")
    cert_info = certs.inspect_certificate(cert_pem)
    info_txt = out_dir / "certificate_info.txt"
    info_txt.write_text("EDUCATIONAL SELF-SIGNED CERTIFICATE - not issued by a trusted CA\n\n"
                        + certs.certificate_text(cert_pem), encoding="utf-8")

    # 3. Verification.
    sig_ok, sig_msg = certs.verify_self_signed(cert_pem)
    raw_sig_ok, raw_sig_msg = certs.verify_certificate_signature(cert_pem, cert_pem, out_dir)
    time_ok = certs.is_currently_valid(cert_pem)
    cert_pub = certs.certificate_public_key(cert_pem)
    key_ok = (cert_pub.n, cert_pub.e) == (sender_key.n, sender_key.e)

    # 4. Negative tests.
    bad_subject = certs.der_to_pem(
        write_file_bytes(out_dir / "tampered_subject_certificate.der", tamper_subject(cert_der.read_bytes())),
        out_dir / "tampered_subject_certificate.pem")
    bad_sig = certs.der_to_pem(
        write_file_bytes(out_dir / "tampered_signature_certificate.der", tamper_signature(cert_der.read_bytes())),
        out_dir / "tampered_signature_certificate.pem")
    # The receiver trusts the genuine certificate (pinned) and checks the modified one against it.
    subj_sig_ok, subj_sig_msg = certs.verify_certificate_signature(bad_subject, cert_pem, out_dir)
    subj_ok, subj_msg = certs.verify_against_anchor(bad_subject, trusted_cert=cert_pem)
    badsig_ok, badsig_msg = certs.verify_self_signed(bad_sig)
    for tmp in (out_dir / "tampered_subject_certificate.der", out_dir / "tampered_signature_certificate.der"):
        tmp.unlink()

    # 5. Use the certificate's public key to verify a signature over the selected file.
    data = read_file_bytes(info.path)
    file_sig = sign_pss(data, sender_key)
    sig_path = write_file_bytes(out_dir / f"{info.name}.sig", file_sig)
    file_sig_ok = verify_pss(data, file_sig, cert_pub)

    passed = (sig_ok and raw_sig_ok and time_ok and key_ok and not subj_sig_ok and not subj_ok
              and not badsig_ok and file_sig_ok)
    result = TaskResult(TASK_ID, TITLE, status=Status.PASS if passed else Status.FAIL)
    if not passed:
        result.reason = "Certificate verification did not behave as expected."
    ok = lambda b: "PASS" if b else "FAIL"  # noqa: E731
    result.add("NOTICE", "Educational self-signed certificate - no trusted CA involved")
    result.add("OpenSSL", version)
    result.add("Subject", cert_info.subject)
    result.add("Issuer", f"{cert_info.issuer}  ({'self-signed' if cert_info.self_signed else 'CA-issued'})")
    result.add("Serial number", cert_info.serial)
    result.add("Public key", f"{cert_info.public_key_algorithm}, {cert_info.public_key_bits} bit, "
                             f"fp {public_key_fingerprint(cert_pub)}")
    result.add("Validity: not before", cert_info.not_before)
    result.add("Validity: not after", cert_info.not_after)
    result.add("Signature", f"{cert_info.signature_algorithm}, value {cert_info.signature_hex_prefix}...")
    result.add("SHA-256 fingerprint", cert_info.sha256_fingerprint)
    result.add("CA certificate", "yes" if cert_info.is_ca else "no (end-entity, CA:FALSE)")
    result.add("Verify: self-signature + validity", f"{ok(sig_ok)} ({sig_msg})")
    result.add("Verify: signature over TBS", f"{ok(raw_sig_ok)} (openssl dgst -sha256 -verify: {raw_sig_msg})")
    result.add("Verify: not expired now", ok(time_ok))
    result.add("Verify: cert key == sender key", ok(key_ok))
    result.add("Tampered Subject (CN=...Hacker)", f"signature check: {subj_sig_msg}; "
                                                  f"openssl verify: {subj_msg}")
    result.add("Tampered Subject rejected", ok(not subj_sig_ok and not subj_ok))
    result.add("Tampered signature rejected", f"{ok(not badsig_ok)} ({badsig_msg})")
    result.add("File signature via cert key", f"{ok(file_sig_ok)} - {info.name} signed by sender, verified "
                                              f"with public key from certificate")
    result.add("Private key location", f"{key_path} (git-ignored, not in outputs)")
    result.artifacts += [cert_pem, cert_der, info_txt, bad_subject, bad_sig, sig_path]
    result.data = {
        "subject": cert_info.subject, "issuer": cert_info.issuer, "serial": cert_info.serial,
        "not_before": cert_info.not_before, "not_after": cert_info.not_after,
        "public_key_bits": cert_info.public_key_bits, "signature_algorithm": cert_info.signature_algorithm,
        "sha256_fingerprint": cert_info.sha256_fingerprint, "self_signed": cert_info.self_signed,
        "verified": sig_ok, "tbs_signature_valid": raw_sig_ok, "currently_valid": time_ok,
        "key_matches": key_ok, "tampered_subject_rejected": not subj_ok and not subj_sig_ok, "tampered_signature_rejected": not badsig_ok,
        "file_signature_verified_with_cert": file_sig_ok,
    }
    result.details = (
        "A certificate binds a public key to an identity (the Subject). The Issuer vouches\n"
        "for that binding with its signature over all the fields. For a self-signed\n"
        "certificate, Issuer and Subject are the same, so it proves possession of the\n"
        "private key but not identity. It can be trusted only if the receiver got it through\n"
        "a trusted channel, e.g. by comparing the SHA-256 fingerprint out of band.\n"
        "In real PKI a trusted Certificate Authority signs it, and the verifier checks the\n"
        "chain to a root CA, the validity dates, key usage, and revocation (CRL/OCSP).\n"
        "Revocation is not modelled here.\n"
        "Verification uses 'openssl verify -check_ss_sig'. Without this flag OpenSSL does not\n"
        "check the signature of a certificate that is its own trust anchor, so a tampered\n"
        "self-signed certificate would wrongly report OK."
    )
    result.save(out_dir)
    return result


if __name__ == "__main__":
    cli_main(run, __doc__.splitlines()[0])
