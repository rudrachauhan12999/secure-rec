# Secure File Exchange & Cryptography Analysis Platform

A project focusing on a working Sender → Receiver
pipeline that encrypts a real file with AES-128-CBC, protects the AES
session key with RSA-OAEP, hashes it with SHA-256, signs it with RSA-PSS,
and attaches a self-signed X.509-style certificate — transmitted over a real
TCP socket — plus a dashboard for exploring every primitive (and attack)
individually.

**Nothing in this project is hardcoded or simulated at the crypto layer.**
Every hash, signature, timing, and encrypted byte is computed live by real
library calls (`pycryptodome` / `cryptography`). See
[`docs/CIPAT-requirement-matrix.md`](docs/CIPAT-requirement-matrix.md) for
exactly which assignment requirement maps to which file.

## Project layout

```
crypto_core/     Real cryptographic primitives (AES/3DES, RSA, DH, SHA-256,
                 certificates, Kerberos simulation, the secure envelope)
pipeline/        Sender / Receiver processes, real TCP socket transport
experiments/     One script per CIPAT sub-requirement, each with a run()
backend/         FastAPI REST API wrapping crypto_core/pipeline/experiments
frontend/        React + Vite dashboard
tests/           pytest suite (unit tests per primitive + one full
                 end-to-end TCP integration test)
data/samples/    Bundled sample text, binary, and image files
data/runs/       Generated run history + experiment outputs (gitignored)
evidence/        User-supplied Wireshark .pcap files and screenshots
docs/            Architecture, concepts, pipeline, experiments, packet
                 analysis, real-world mapping, viva prep, requirement matrix
scripts/         Sample-data generator, setup helpers
```

## Prerequisites

- Python 3.10+ (developed against 3.11)
- Node.js 18+ (developed against 24) with npm
- (Optional, for real packet capture) [Wireshark](https://www.wireshark.org/)

## Setup

```bash
# 1. Python dependencies
pip install -r requirements.txt

# 2. Generate the bundled sample files (idempotent, only needed once)
python scripts/generate_samples.py

# 3. Frontend dependencies
cd frontend
npm install
cd ..
```

Copy `.env.example` to `.env` if you want to change the default ports; the
backend and pipeline scripts fall back to `127.0.0.1:8000`, `127.0.0.1:5173`
(frontend, for CORS) and `127.0.0.1:9443` (pipeline) respectively if unset.

## Running the dashboard

Two processes, in two terminals, from the project root:

```bash
# Terminal 1 -- backend (FastAPI)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2 -- frontend (Vite dev server)
cd frontend
npm run dev
```

Open **http://localhost:5173**. The six tabs:

1. **Overview** — problem statement, security goals, pipeline architecture.
2. **Secure Transfer** — pick a sample file (or upload your own, ≥1KB) and
   run the full real pipeline; see the live stage log and verification
   badges (SHA-256, signature, certificate).
3. **Comparative Analysis** — a live-benchmarked table of every algorithm
   used (purpose, key size, measured speed, known attacks, real-world use).
4. **Experiments** — run each CIPAT sub-requirement independently: AES vs
   3-DES timing, avalanche effect, ECB vs CBC (with generated images), RSA
   hybrid encryption, Diffie-Hellman, the MITM attack + mitigation, tamper
   detection, digital signatures, the self-signed certificate, and the
   Kerberos simulation.
5. **Real-World Mapping** — each layer mapped to the industry protocol it
   mirrors (TLS, PGP, SSH/VPN, enterprise SSO).
6. **Packet Capture Evidence** — upload a *real* Wireshark `.pcap`/`.pcapng`
   capture and a screenshot; the backend parses the capture itself (no
   external tool needed) and shows packet count/protocol/src/dst/port/time,
   alongside "what an eavesdropper can/cannot see."

## Running the pipeline standalone (two processes / two machines)

Useful for a genuine two-terminal demo and for Wireshark capture (the
dashboard's "Run Secure Transfer" runs both ends in-process on one machine):

```bash
# Terminal 1
python -m pipeline.receiver --host 127.0.0.1 --port 9443

# Terminal 2
python -m pipeline.sender --host 127.0.0.1 --port 9443 --file data/samples/sample_document.txt
```

For two machines on the same LAN: run the receiver with `--host 0.0.0.0`
and point the sender's `--host` at the receiver's LAN IP.

## Running the experiments standalone

```bash
python -m experiments.exp_aes_3des_timing
python -m experiments.exp_avalanche
python -m experiments.exp_ecb_vs_cbc
python -m experiments.exp_hybrid_rsa
python -m experiments.exp_dh_shared_secret
python -m experiments.exp_mitm_dh
python -m experiments.exp_tamper_detection
python -m experiments.exp_signature
python -m experiments.exp_certificate
python -m experiments.exp_kerberos
```

Each prints a JSON result to stdout and saves it under
`data/runs/experiments/` (the `ecb-vs-cbc` experiment also saves two BMP
images there for visual comparison).

## Packet capture / Wireshark evidence

See [`docs/packet-analysis.md`](docs/packet-analysis.md) for the full
capture procedure. Summary: run the Sender/Receiver as two separate
processes (above), capture on the loopback (or LAN) interface in Wireshark
while the transfer runs, save the `.pcap`/`.pcapng`, screenshot the Wireshark
window, and upload both on the dashboard's Packet Capture Evidence page.

## Running the tests

```bash
python -m pytest tests/ -v
```

40 tests covering every primitive individually (AES/DES/3DES round trips,
avalanche bounds, ECB-leaks-CBC-doesn't, RSA-OAEP, RSA-PSS signatures
verified correctly and shown failing under three tamper scenarios, real +
toy Diffie-Hellman, the MITM attack and its
signature-based mitigation, certificate issue/verify/tamper/expiry, the
Kerberos exchange, the pcap/pcapng parser, and the full envelope round trip
including tamper detection) plus one real end-to-end integration test that
runs an actual Sender and Receiver over a real TCP socket and diffs the
received file against the original byte-for-byte.

## Documentation

| File | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Component diagram, pipeline sequence diagram |
| [`docs/cryptography-concepts.md`](docs/cryptography-concepts.md) | What each primitive does and why |
| [`docs/pipeline.md`](docs/pipeline.md) | Stage-by-stage breakdown + failure modes |
| [`docs/experiments.md`](docs/experiments.md) | What each experiment proves and how to read its output |
| [`docs/packet-analysis.md`](docs/packet-analysis.md) | How to capture and what the parser extracts |
| [`docs/real-world-mapping.md`](docs/real-world-mapping.md) | Mapping to TLS/PGP/SSH/VPN/enterprise auth |
| [`docs/viva-preparation.md`](docs/viva-preparation.md) | Anticipated questions with short answers |
| [`docs/CIPAT-requirement-matrix.md`](docs/CIPAT-requirement-matrix.md) | Every assignment requirement → file → dashboard page → evidence |

## Notes on this machine's RSA key-generation speed

RSA-2048 key generation was measured taking 0.6–4s on the development
machine (vs. the sub-200ms typical on faster hardware) — the pipeline and
experiments account for this with generous timeouts, but if a request feels
slow, that's why.
