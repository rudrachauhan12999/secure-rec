"""Local TCP sender/receiver for Wireshark analysis of the protected package.

Separate from the in-process pipeline: it sends a package created earlier by
``python -m pipeline.secure_pipeline`` over a real TCP connection.

    # 1. create keys, trust store and the package
    python -m pipeline.secure_pipeline data/student_records.txt
    # 2. terminal A - receiver
    python -m pipeline.network_demo --server
    # 3. terminal B - sender
    python -m pipeline.network_demo --client outputs/integrated_pipeline/sender/transfer_package.srpkg

    # tamper demo: `secure_pipeline --tamper` writes BOTH the genuine and the
    # tampered package from the same keys; start the server with --count 2 and
    # send sender/transfer_package.srpkg then tamper/tampered_transfer_package.srpkg.
    # Every pipeline run generates new keys - restart the server after re-running it.

Protocol (TCP, default 127.0.0.1:5055, one package per connection)
    Client -> Server : b"SRPKG1" | uint64 big-endian length | package bytes
    Server -> Client : b"SRACK1" | uint64 big-endian length | JSON
                       {"status": "ACCEPTED"|"REJECTED", "failed_stage": str|null,
                        "received_bytes": int, "package_sha256": hex}

The package is the JSON document described in pipeline/package.py: header,
public certificate, RSA-wrapped key, IVs, AES ciphertexts and signature.
No plaintext, raw session key or private key is ever sent.  The reply
contains only the verdict and a hash of the *package* (not of the file).

What Wireshark shows (capture on the loopback adapter - on Windows install
Npcap with "loopback support" and pick "Adapter for loopback traffic
capture"; display filter ``tcp.port == 5055``; Follow > TCP Stream):
  visible:     IP addresses/ports, timing, sizes, the header (algorithms,
               sender name, receiver-key fingerprint), the public certificate,
               base64 ciphertext/signature, the ACCEPTED/REJECTED reply
  not visible: file name, file contents, file SHA-256 (all encrypted), the
               session key, any private key
The transport itself is plain TCP (no TLS) on purpose, so the capture shows
that the application-layer protection alone keeps the content confidential.

The receiver loads its private key and trust store from
keys/integrated_pipeline/ (written by the pipeline run) and saves an
accepted file to outputs/integrated_pipeline/network_received/.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from pathlib import Path

from Crypto.PublicKey import RSA

from core.config import KEYS_DIR, OUTPUT_DIR
from core.file_handler import write_file_bytes
from core.hashing import sha256_bytes
from core.logging_utils import get_logger
from pipeline.receiver import ReceiverOutcome, TrustStore, receive_package

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5055
REQUEST_MAGIC = b"SRPKG1"
REPLY_MAGIC = b"SRACK1"
MAX_FRAME = 300 * 1024 * 1024
SOCKET_TIMEOUT = 30.0
DEFAULT_KEYS = KEYS_DIR / "integrated_pipeline"
DEFAULT_OUTPUT = OUTPUT_DIR / "integrated_pipeline" / "network_received"

_log = get_logger("network_demo")


class ProtocolError(Exception):
    pass


# ------------------------------------------------------------------ framing
def send_frame(sock: socket.socket, magic: bytes, payload: bytes) -> None:
    sock.sendall(magic + struct.pack(">Q", len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ProtocolError("connection closed before the full frame arrived")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket, magic: bytes, max_len: int = MAX_FRAME) -> bytes:
    header = _recv_exact(sock, len(magic) + 8)
    if header[:len(magic)] != magic:
        raise ProtocolError("unexpected frame type")
    (length,) = struct.unpack(">Q", header[len(magic):])
    if length > max_len:
        raise ProtocolError(f"frame too large ({length} bytes)")
    return _recv_exact(sock, length)


# ------------------------------------------------------------------- server
class ReceiverServer:
    """Receives packages and runs the full receiver verification on each."""

    def __init__(self, keys_dir: Path = DEFAULT_KEYS, output_dir: Path = DEFAULT_OUTPUT,
                 host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        key_path, trust_path = keys_dir / "receiver_private_key.pem", keys_dir / "trust_store.json"
        if not key_path.exists() or not trust_path.exists():
            raise FileNotFoundError(f"receiver key/trust store not found in {keys_dir}; "
                                    "run 'python -m pipeline.secure_pipeline' first")
        self._receiver_key = RSA.import_key(key_path.read_bytes())
        self.trust = TrustStore.load(trust_path)
        self.output_dir = output_dir
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(5)
        self.address = self._sock.getsockname()
        self.last_outcome: ReceiverOutcome | None = None

    def handle(self, conn: socket.socket, peer) -> dict:
        conn.settimeout(SOCKET_TIMEOUT)
        blob = recv_frame(conn, REQUEST_MAGIC)
        _log.info("received %d-byte package from %s:%s (SHA-256 %s)", len(blob), *peer[:2], sha256_bytes(blob)[:16])
        outcome = receive_package(blob, self._receiver_key, self.trust, self.output_dir / "work")
        self.last_outcome = outcome
        if outcome.accepted:
            safe_name = Path(str(outcome.manifest.get("filename", ""))).name or "recovered.bin"
            path = write_file_bytes(self.output_dir / f"recovered_{safe_name}", outcome.recovered)
            _log.info("ACCEPTED - all checks passed, recovered file written to %s", path)
        else:
            _log.warning("REJECTED at stage '%s'", outcome.failed_stage)
        reply = {"status": "ACCEPTED" if outcome.accepted else "REJECTED", "failed_stage": outcome.failed_stage,
                 "received_bytes": len(blob), "package_sha256": sha256_bytes(blob)}
        send_frame(conn, REPLY_MAGIC, json.dumps(reply).encode())
        return reply

    def serve(self, max_connections: int | None = 1) -> None:
        """Handle ``max_connections`` packages (None = until interrupted)."""
        _log.info("receiver listening on %s:%s", *self.address[:2])
        handled = 0
        try:
            while max_connections is None or handled < max_connections:
                conn, peer = self._sock.accept()
                with conn:
                    try:
                        self.handle(conn, peer)
                    except (ProtocolError, OSError) as exc:
                        _log.error("connection from %s:%s failed: %s", *peer[:2], exc)
                handled += 1
        finally:
            self.close()

    def close(self) -> None:
        self._sock.close()


# ------------------------------------------------------------------- client
def send_package(package: bytes | Path, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 timeout: float = SOCKET_TIMEOUT) -> dict:
    blob = package.read_bytes() if isinstance(package, Path) else package
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_frame(sock, REQUEST_MAGIC, blob)
        return json.loads(recv_frame(sock, REPLY_MAGIC, max_len=64 * 1024))


def main() -> None:
    parser = argparse.ArgumentParser(description="Local TCP transfer of a SECURE-REC package (for Wireshark)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", action="store_true", help="run the receiver")
    mode.add_argument("--client", metavar="PACKAGE", help="send this .srpkg package")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--count", type=int, default=1, help="server: packages to accept before exiting (0 = forever)")
    parser.add_argument("--keys", default=str(DEFAULT_KEYS), help="server: key/trust-store directory")
    args = parser.parse_args()

    if args.server:
        try:
            server = ReceiverServer(Path(args.keys), DEFAULT_OUTPUT, args.host, args.port)
        except (FileNotFoundError, OSError) as exc:
            sys.exit(f"error: {exc}")
        server.serve(None if args.count == 0 else args.count)
        return

    package = Path(args.client)
    if not package.is_file():
        sys.exit(f"error: package not found: {package}")
    try:
        reply = send_package(package, args.host, args.port)
    except (OSError, ProtocolError) as exc:
        sys.exit(f"error: could not deliver package: {exc}")
    print(json.dumps(reply, indent=2))
    sys.exit(0 if reply.get("status") == "ACCEPTED" else 1)


if __name__ == "__main__":
    main()
