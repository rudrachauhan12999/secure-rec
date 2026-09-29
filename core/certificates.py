"""X.509 certificate generation/inspection/verification via the OpenSSL CLI.

The RSA key pair is generated with PyCryptodome (``core.key_manager``) and
handed to OpenSSL, which builds and self-signs the certificate.  All
verification is done by OpenSSL as well.

Private keys are written ONLY to the git-ignored ``keys/`` directory, never to
``outputs/``.

Note on verifying self-signed certificates: when a certificate is its own
trust anchor, ``openssl verify`` does not check the anchor's signature by
default (anchors are trusted by configuration).  ``-check_ss_sig`` forces
that check, so a tampered self-signed certificate is rejected.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import RSA

_WINDOWS_CANDIDATES = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    r"C:\Program Files\OpenSSL\bin\openssl.exe",
]


class OpenSSLNotFound(RuntimeError):
    pass


class OpenSSLError(RuntimeError):
    pass


def find_openssl() -> str:
    """Locate the OpenSSL executable (env var OPENSSL_BIN overrides)."""
    env = os.environ.get("OPENSSL_BIN")
    if env and Path(env).is_file():
        return env
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in _WINDOWS_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    raise OpenSSLNotFound(
        "OpenSSL executable not found. Install OpenSSL (it ships with Git for Windows) "
        "and add it to PATH, or set the OPENSSL_BIN environment variable."
    )


def run_openssl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run([find_openssl(), *args], capture_output=True, text=True, timeout=60)
    if check and proc.returncode != 0:
        raise OpenSSLError(f"openssl {args[0]} failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc


def openssl_version() -> str:
    return run_openssl("version").stdout.strip()


def write_private_key(key: RSA.RsaKey, path: Path) -> Path:
    """Store an RSA private key (PKCS#8 PEM) with owner-only permissions where supported."""
    if not key.has_private():
        raise ValueError("expected a private key")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.export_key(format="PEM", pkcs=8))
    try:
        os.chmod(path, 0o600)  # effective on POSIX; limited effect on Windows
    except OSError:
        pass
    return path


def build_subject(fields: dict[str, str]) -> str:
    """{'C': 'IN', 'CN': 'x'} -> '/C=IN/CN=x' (with '/' escaped inside values)."""
    return "".join(f"/{k}={v.replace('/', chr(92) + '/')}" for k, v in fields.items())


def create_self_signed_certificate(private_key_path: Path, cert_path: Path, subject: dict[str, str],
                                   days: int = 365) -> Path:
    """Self-signed X.509 v3 end-entity certificate, signed with SHA-256/RSA."""
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    run_openssl(
        "req", "-x509", "-new", "-key", str(private_key_path), "-sha256", "-days", str(days),
        "-subj", build_subject(subject),
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "subjectKeyIdentifier=hash",
        "-out", str(cert_path),
    )
    return cert_path


def pem_to_der(cert_pem: Path, der_path: Path) -> Path:
    run_openssl("x509", "-in", str(cert_pem), "-outform", "DER", "-out", str(der_path))
    return der_path


def der_to_pem(der_path: Path, pem_path: Path) -> Path:
    run_openssl("x509", "-inform", "DER", "-in", str(der_path), "-out", str(pem_path))
    return pem_path


def certificate_text(cert_path: Path) -> str:
    """Full human-readable dump (``openssl x509 -text``)."""
    return run_openssl("x509", "-in", str(cert_path), "-noout", "-text").stdout


def certificate_public_key(cert_path: Path) -> RSA.RsaKey:
    """Extract the subject public key from the certificate (via OpenSSL)."""
    pem = run_openssl("x509", "-in", str(cert_path), "-noout", "-pubkey").stdout
    return RSA.import_key(pem)


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    public_key_algorithm: str
    public_key_bits: int
    signature_algorithm: str
    signature_hex_prefix: str
    sha256_fingerprint: str
    is_ca: bool

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer


def _field(text: str, pattern: str, default: str = "") -> str:
    m = re.search(pattern, text, re.MULTILINE)
    return m.group(1).strip() if m else default


def inspect_certificate(cert_path: Path) -> CertificateInfo:
    summary = run_openssl("x509", "-in", str(cert_path), "-noout", "-subject", "-issuer", "-serial",
                          "-startdate", "-enddate", "-fingerprint", "-sha256").stdout
    text = certificate_text(cert_path)
    # Signature value: the hex block after the final "Signature Value:" / "Signature Algorithm:" header.
    sig_block = re.split(r"Signature Value:|\n    Signature Algorithm:[^\n]*\n", text)[-1]
    sig_hex = re.sub(r"[^0-9a-f]", "", sig_block.lower())
    return CertificateInfo(
        subject=_field(summary, r"^subject=(.*)$"),
        issuer=_field(summary, r"^issuer=(.*)$"),
        serial=_field(summary, r"^serial=(.*)$"),
        not_before=_field(summary, r"^notBefore=(.*)$"),
        not_after=_field(summary, r"^notAfter=(.*)$"),
        public_key_algorithm=_field(text, r"Public Key Algorithm:\s*(.*)$"),
        public_key_bits=int(_field(text, r"Public-Key:\s*\((\d+) bit\)", "0")),
        signature_algorithm=_field(text, r"Signature Algorithm:\s*(.*)$"),
        signature_hex_prefix=sig_hex[:32],
        sha256_fingerprint=_field(summary, r"Fingerprint=(.*)$"),
        is_ca="CA:TRUE" in text,
    )


def _openssl_verify(cert_path: Path, anchor: Path) -> tuple[bool, str]:
    proc = run_openssl("verify", "-check_ss_sig", "-CAfile", str(anchor), str(cert_path), check=False)
    lines = [ln.strip() for ln in (proc.stdout + proc.stderr).splitlines() if ln.strip()]
    if proc.returncode == 0:
        return True, next((ln for ln in lines if ln.endswith(": OK")), "OK")
    reason = next((ln for ln in lines if ln.startswith("error") and "lookup" in ln), lines[0] if lines else "")
    return False, reason


def verify_self_signed(cert_path: Path) -> tuple[bool, str]:
    """Check the self-signature and validity period with the certificate as its own anchor."""
    return _openssl_verify(cert_path, cert_path)


def verify_against_anchor(cert_path: Path, trusted_cert: Path) -> tuple[bool, str]:
    """Verify ``cert_path`` using a previously trusted (pinned) certificate as the anchor."""
    return _openssl_verify(cert_path, trusted_cert)


def _der_element(buf: bytes, pos: int) -> tuple[int, int]:
    """Return (content_start, element_end) of the DER TLV starting at ``pos``."""
    length, header = buf[pos + 1], 2
    if length & 0x80:
        n = length & 0x7F
        length, header = int.from_bytes(buf[pos + 2:pos + 2 + n], "big"), 2 + n
    return pos + header, pos + header + length


def split_certificate(cert_der: bytes) -> tuple[bytes, bytes]:
    """Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }.

    Returns (tbs_bytes, signature_bytes): exactly what the issuer signed and the signature.
    """
    body, _ = _der_element(cert_der, 0)
    _, tbs_end = _der_element(cert_der, body)
    _, alg_end = _der_element(cert_der, tbs_end)
    sig_start, sig_end = _der_element(cert_der, alg_end)
    return cert_der[body:tbs_end], cert_der[sig_start + 1:sig_end]  # skip 'unused bits' byte


def verify_certificate_signature(cert_path: Path, issuer_cert: Path, work_dir: Path) -> tuple[bool, str]:
    """Check the issuer's SHA-256/RSA signature over the TBSCertificate with OpenSSL.

    This isolates the signature check from the rest of path validation, so a
    modified field shows up precisely as a signature mismatch.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    der = work_dir / "_cert.der"
    tbs_path, sig_path, pub_path = work_dir / "_tbs.der", work_dir / "_sig.bin", work_dir / "_issuer_pub.pem"
    try:
        pem_to_der(cert_path, der)
        tbs, sig = split_certificate(der.read_bytes())
        tbs_path.write_bytes(tbs)
        sig_path.write_bytes(sig)
        pub_path.write_text(run_openssl("x509", "-in", str(issuer_cert), "-noout", "-pubkey").stdout)
        proc = run_openssl("dgst", "-sha256", "-verify", str(pub_path), "-signature", str(sig_path),
                           str(tbs_path), check=False)
        return proc.returncode == 0, (proc.stdout.strip() or proc.stderr.strip().splitlines()[0])
    finally:
        for p in (der, tbs_path, sig_path, pub_path):
            p.unlink(missing_ok=True)


def is_currently_valid(cert_path: Path) -> bool:
    """``-checkend 0``: exit status 0 if the certificate has not expired right now."""
    return run_openssl("x509", "-in", str(cert_path), "-noout", "-checkend", "0", check=False).returncode == 0
