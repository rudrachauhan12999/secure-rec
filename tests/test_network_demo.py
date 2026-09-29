"""Local TCP network demo: real sockets on 127.0.0.1, with a capturing relay
standing in for Wireshark to check exactly which bytes cross the wire."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from core import certificates as certs
from core.file_handler import describe_file
from core.results import Status
from pipeline import network_demo as nd
from pipeline import secure_pipeline as sp
from pipeline.sender import SenderIdentity, build_manifest, seal_package


@pytest.fixture(autouse=True)
def _require_openssl():
    try:
        certs.find_openssl()
    except certs.OpenSSLNotFound:
        pytest.skip("OpenSSL not installed")


@pytest.fixture
def prepared(tmp_path, sample_file, rsa_identities):
    """Run the pipeline once (keys, trust store, genuine + tampered packages)."""
    out_root, keys_dir = tmp_path / "out", tmp_path / "keys"
    result = sp.run(sample_file, output_root=out_root, keys_dir=keys_dir, tamper="ciphertext",
                    sender_key=rsa_identities["sender"], receiver_key=rsa_identities["receiver"])
    assert result.status is Status.PASS
    base = out_root / sp.TASK_ID
    return {"keys": keys_dir, "out": tmp_path / "net", "genuine": base / "sender" / sp.PACKAGE_NAME,
            "tampered": base / "tamper" / f"tampered_{sp.PACKAGE_NAME}", "cert": base / "sender" /
            "sender_certificate.pem"}


def start_server(prepared, connections=1):
    server = nd.ReceiverServer(prepared["keys"], prepared["out"], "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve, args=(connections,), daemon=True)
    thread.start()
    return server, thread


def start_capturing_relay(target_port):
    """Minimal TCP relay recording both directions (what a packet capture would contain)."""
    captured = {"client_to_server": b"", "server_to_client": b""}
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    def relay():
        conn, _ = lsock.accept()
        with conn, socket.create_connection(("127.0.0.1", target_port)) as up:
            header = b""
            while len(header) < 14:
                header += conn.recv(14 - len(header))
            (length,) = struct.unpack(">Q", header[6:])
            body = b""
            while len(body) < length:
                body += conn.recv(65536)
            captured["client_to_server"] = header + body
            up.sendall(header + body)
            reply = b""
            while chunk := up.recv(65536):
                reply += chunk
            captured["server_to_client"] = reply
            conn.sendall(reply)
        lsock.close()

    threading.Thread(target=relay, daemon=True).start()
    return lsock.getsockname()[1], captured


def test_network_transfer_accepted_and_no_plaintext_on_wire(prepared, sample_file, rsa_identities):
    server, thread = start_server(prepared)
    port, captured = start_capturing_relay(server.address[1])
    reply = nd.send_package(prepared["genuine"], "127.0.0.1", port)
    thread.join(10)
    assert reply["status"] == "ACCEPTED" and reply["failed_stage"] is None
    assert (prepared["out"] / f"recovered_{sample_file.name}").read_bytes() == sample_file.read_bytes()

    wire = captured["client_to_server"] + captured["server_to_client"]
    assert captured["client_to_server"].startswith(nd.REQUEST_MAGIC)
    data = sample_file.read_bytes()
    for i in range(0, len(data) - 32, 2048):
        assert data[i:i + 32] not in wire                              # no plaintext
    assert b"student_records" not in wire                              # no file name
    assert describe_file(sample_file).name.encode() not in wire
    assert b"PRIVATE KEY" not in wire
    for key in rsa_identities.values():
        assert format(key.d, "x")[:48].encode() not in wire
    import hashlib
    assert hashlib.sha256(data).hexdigest().encode() not in wire       # not even the file hash


def test_tampered_package_rejected_over_network(prepared):
    server, thread = start_server(prepared)
    reply = nd.send_package(prepared["tampered"], "127.0.0.1", server.address[1])
    thread.join(10)
    assert reply == {**reply, "status": "REJECTED", "failed_stage": "Digital signature"}
    assert not any(prepared["out"].glob("recovered_*"))


def test_server_survives_malformed_frame(prepared):
    server, thread = start_server(prepared, connections=2)
    with socket.create_connection(server.address) as s:
        s.sendall(b"GARBAGE-NOT-A-FRAME")
    reply = nd.send_package(prepared["genuine"], "127.0.0.1", server.address[1])
    thread.join(10)
    assert reply["status"] == "ACCEPTED"


def test_recovered_filename_cannot_escape_output_dir(prepared, rsa_identities, tmp_path, sample_file):
    """A (signed) manifest claiming '../../evil.txt' is saved inside the output dir only."""
    identity = SenderIdentity(rsa_identities["sender"], prepared["cert"].read_text(), prepared["cert"],
                              "SECURE-REC Sender")
    data = b"payload"
    manifest = dict(build_manifest(describe_file(sample_file), data), filename="../../evil.txt")
    package, _ = seal_package(data, manifest, identity, rsa_identities["receiver"].publickey())
    server, thread = start_server(prepared)
    assert nd.send_package(package.to_bytes(), "127.0.0.1", server.address[1])["status"] == "ACCEPTED"
    thread.join(10)
    assert (prepared["out"] / "recovered_evil.txt").read_bytes() == data
    assert not (prepared["out"].parent.parent / "evil.txt").exists()


def test_frame_limits_and_missing_keys(tmp_path):
    a, b = socket.socketpair()
    with a, b:
        a.sendall(nd.REQUEST_MAGIC + struct.pack(">Q", nd.MAX_FRAME + 1))
        with pytest.raises(nd.ProtocolError):
            nd.recv_frame(b, nd.REQUEST_MAGIC)
    with pytest.raises(FileNotFoundError):
        nd.ReceiverServer(tmp_path / "no-keys", tmp_path / "out", "127.0.0.1", 0)
