"""Cross-task check: run every key-handling task into one output tree and scan
all generated files for private-key material."""

from __future__ import annotations

from core import certificates as certs
from tasks import (task05_hybrid, task06_diffie_hellman, task07_mitm, task09_tampering,
                   task10_signature, task11_certificate, task12_kerberos)


def test_no_private_keys_anywhere_in_outputs(tmp_path, out_root, binary_file, rsa_identities):
    task05_hybrid.run(binary_file, output_root=out_root, receiver_key=rsa_identities["receiver"],
                      check_wrong_key=False)
    task06_diffie_hellman.run(output_root=out_root)
    task07_mitm.run(binary_file, output_root=out_root, identity_keys=rsa_identities)
    task09_tampering.run(binary_file, output_root=out_root)
    task10_signature.run(binary_file, output_root=out_root, signing_key=rsa_identities["sender"],
                         impostor_key=rsa_identities["attacker"])
    try:
        certs.find_openssl()
        task11_certificate.run(binary_file, output_root=out_root, keys_dir=tmp_path / "keys",
                               sender_key=rsa_identities["sender"])
    except certs.OpenSSLNotFound:
        pass
    task12_kerberos.run(output_root=out_root)

    markers = [b"PRIVATE KEY"]
    for key in rsa_identities.values():
        body = "".join(key.export_key().decode().splitlines()[1:-1])
        markers += [body[:48].encode(), format(key.d, "x")[:48].encode()]
    files = [f for f in out_root.rglob("*") if f.is_file()]
    assert len(files) > 20
    for f in files:
        content = f.read_bytes()
        for marker in markers:
            assert marker not in content, f"secret material found in {f}"
