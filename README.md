# Secure File Exchange & Cryptography Analysis Platform

A secure file exchange and cryptography analysis platform that demonstrates how a file can be protected and delivered from a **Sender** to a **Receiver** using multiple real cryptographic primitives.

The platform implements a complete working pipeline using **AES-128-CBC** for file encryption, **RSA-OAEP** for protecting the AES session key, **SHA-256** for integrity verification, **RSA-PSS** for digital signatures, and a **self-signed X.509-style certificate** for identity verification.

The encrypted payload is transmitted through a **real TCP socket**, while a web-based dashboard allows each cryptographic primitive, experiment, attack scenario, and packet-level behavior to be explored independently.

**Nothing in the cryptographic layer is hardcoded or simulated.**

Every hash, signature, encryption operation, timing measurement, and encrypted byte is generated live using real cryptographic libraries such as `PyCryptodome` and `cryptography`.

---

## Why This Project Exists

Understanding cryptography is difficult when individual algorithms are studied only as isolated mathematical concepts.

A secure communication system does not normally rely on a single primitive. Encryption, key exchange, integrity verification, authentication, digital signatures, and certificates work together as different layers of the same security system.

This project was built to make that complete process visible.

Instead of simply showing that a file was encrypted, the platform demonstrates:

- how the file is encrypted
- how the encryption key is protected
- how integrity is verified
- how authenticity is established
- how certificates are used
- what happens when data is modified
- how attacks such as Diffie-Hellman MITM can occur
- what an eavesdropper can observe from network packets
- how the individual cryptographic algorithms compare

The result is a single platform where the **implementation, experiments, attacks, network transmission, and security analysis** can all be explored.

---

## What the Platform Does

### Secure File Transfer

- Accepts a real file from a Sender.
- Generates a real AES session key.
- Encrypts the file using AES-128-CBC.
- Protects the AES session key using RSA-OAEP.
- Generates a SHA-256 hash for integrity verification.
- Creates an RSA-PSS digital signature.
- Attaches a self-signed X.509-style certificate.
- Sends the secure envelope through a real TCP socket.
- Allows the Receiver to decrypt and verify the received file.
- Detects tampering during verification.

### Cryptography Experiments

The platform also provides independent experiments for:

- AES vs 3-DES performance
- Avalanche effect
- ECB vs CBC
- RSA hybrid encryption
- Diffie-Hellman shared-secret generation
- Diffie-Hellman MITM attack
- MITM mitigation using signatures
- Tamper detection
- Digital signatures
- Certificate generation and verification
- Kerberos authentication simulation

### Network Analysis

The platform supports real packet-capture evidence using Wireshark.

A captured `.pcap` or `.pcapng` file can be uploaded and parsed by the backend to display:

- packet count
- protocols
- source and destination addresses
- ports
- timestamps
- observable network information
- information that remains protected from an eavesdropper

---

## What the Platform Does NOT Do

To keep the scope clear:

- It does not claim to replace production TLS, PGP, SSH, VPN, or enterprise authentication systems.
- It does not simulate the cryptographic primitives used in the main secure-transfer pipeline.
- It does not hardcode ciphertext, hashes, signatures, or timing results.
- It does not treat Wireshark screenshots as automatically generated evidence.
- It does not claim that a self-signed certificate provides the same trust model as a certificate issued by a public CA.
- It does not provide a production-grade secure file-sharing service.

The project is primarily an **educational implementation, experimentation, and security-analysis platform**.

---

## Supported Scope

The current platform provides:

- **Input:** sample files or user-uploaded files
- **Secure transfer:** Sender → TCP → Receiver
- **Symmetric encryption:** AES-128-CBC
- **Key protection:** RSA-OAEP
- **Integrity:** SHA-256
- **Authentication / non-repudiation demonstration:** RSA-PSS
- **Certificate:** self-signed X.509-style certificate
- **Network transport:** real TCP socket
- **Experiments:** independent cryptography and attack demonstrations
- **Packet analysis:** `.pcap` / `.pcapng` parsing
- **Testing:** unit tests and end-to-end TCP integration testing
- **Dashboard:** web interface for exploring the complete system

---

## Tech Stack

### Frontend

- React
- Vite
- TypeScript

### Backend

- Python
- FastAPI

### Cryptography

- PyCryptodome
- `cryptography`

### Networking

- Python TCP sockets

### Testing

- pytest

### Network Analysis

- Wireshark
- `.pcap` / `.pcapng` packet parsing

### Development

- Python 3.10+
- Node.js 18+
- npm

---

## Installation

### Prerequisites

- Python 3.10 or later
- Node.js 18 or later
- npm
- Wireshark *(optional, required only for real packet-capture evidence)*

### Python Dependencies

From the project root:

```bash
pip install -r requirements.txt
```

### Generate Sample Files

The project includes a sample-data generator:

```bash
python scripts/generate_samples.py
```

This operation is idempotent and only needs to be performed when the bundled sample files need to be generated.

### Frontend Dependencies

```bash
cd frontend
npm install
cd ..
```

---

## Environment Variables

Copy `.env.example` to `.env` if you want to change the default configuration.

The application falls back to:

```text
Backend:   127.0.0.1:8000
Frontend:  127.0.0.1:5173
Pipeline:  127.0.0.1:9443
```

These values can be changed through the environment configuration.

---

## Project Structure

```text
secure-file-exchange/
│
├── crypto_core/
│   ├── AES / 3DES
│   ├── RSA
│   ├── Diffie-Hellman
│   ├── SHA-256
│   ├── Digital signatures
│   ├── Certificates
│   ├── Kerberos simulation
│   └── Secure envelope
│
├── pipeline/
│   ├── sender.py
│   └── receiver.py
│
├── experiments/
│   ├── exp_aes_3des_timing.py
│   ├── exp_avalanche.py
│   ├── exp_ecb_vs_cbc.py
│   ├── exp_hybrid_rsa.py
│   ├── exp_dh_shared_secret.py
│   ├── exp_mitm_dh.py
│   ├── exp_tamper_detection.py
│   ├── exp_signature.py
│   ├── exp_certificate.py
│   └── exp_kerberos.py
│
├── backend/
│   └── FastAPI application
│
├── frontend/
│   └── React + Vite dashboard
│
├── tests/
│   └── pytest test suite
│
├── data/
│   ├── samples/
│   └── runs/
│
├── evidence/
│   └── Wireshark captures and screenshots
│
├── docs/
│   ├── architecture.md
│   ├── cryptography-concepts.md
│   ├── pipeline.md
│   ├── experiments.md
│   ├── packet-analysis.md
│   ├── real-world-mapping.md
│   ├── viva-preparation.md
│   └── CIPAT-requirement-matrix.md
│
├── scripts/
│   └── generate_samples.py
│
├── requirements.txt
└── README.md
```

---

## Application Workflow

The complete application follows a sequence of explicit stages:

```text
User
  ↓
Select / Upload File
  ↓
Sender
  ↓
Generate AES Session Key
  ↓
AES-128-CBC Encryption
  ↓
SHA-256 Hash
  ↓
RSA-PSS Digital Signature
  ↓
RSA-OAEP Encryption of AES Key
  ↓
Attach Certificate
  ↓
Secure Envelope
  ↓
Real TCP Socket
  ↓
Receiver
  ↓
Certificate Verification
  ↓
RSA-OAEP Key Recovery
  ↓
AES Key Recovery
  ↓
AES-128-CBC Decryption
  ↓
SHA-256 Verification
  ↓
RSA-PSS Signature Verification
  ↓
Original File Recovered
```

Each major stage produces information that can be inspected through the dashboard.

There is no hidden stage that silently changes the transfer state.

---

## Secure Cryptographic Pipeline

The secure envelope combines several cryptographic primitives, with each one serving a different purpose.

### 1. AES-128-CBC

The actual file contents are encrypted using **AES-128 in CBC mode**.

AES provides efficient symmetric encryption for the potentially large file payload.

```text
Plaintext File
      ↓
AES-128-CBC
      ↓
Ciphertext
```

### 2. RSA-OAEP

The AES session key itself is protected using RSA-OAEP.

This creates a hybrid encryption design:

```text
File
 ↓
AES Encryption
 ↓
Ciphertext

AES Session Key
 ↓
RSA-OAEP
 ↓
Encrypted AES Key
```

The file does not need to be encrypted directly with RSA, avoiding the limitations of using public-key encryption for large data.

### 3. SHA-256

A SHA-256 digest is generated for the relevant file/envelope data.

The Receiver independently calculates the digest and compares it with the transmitted value.

```text
Original Data
     ↓
SHA-256
     ↓
Digest
```

A mismatch indicates that the data has changed.

### 4. RSA-PSS

The integrity-related data is digitally signed using RSA-PSS.

The Receiver verifies the signature using the corresponding public key.

```text
Hash / Signed Data
       ↓
    RSA-PSS
       ↓
   Signature
```

This provides a demonstration of how digital signatures can establish authenticity and detect unauthorized modification.

### 5. Self-Signed Certificate

A self-signed X.509-style certificate is attached to the secure exchange.

The certificate experiment demonstrates:

- certificate creation
- certificate verification
- certificate tampering
- certificate expiry handling

Because it is self-signed, it demonstrates certificate mechanics rather than the complete public CA trust hierarchy used on the Internet.

---

## Dashboard

The web dashboard is organized into six major areas.

### 1. Overview

Provides:

- project objective
- security goals
- cryptographic architecture
- overall pipeline

### 2. Secure Transfer

Allows the user to:

- select a bundled sample file
- upload a custom file
- execute the complete secure-transfer pipeline
- observe the live stage log
- inspect verification results

Verification includes:

- SHA-256
- digital signature
- certificate

### 3. Comparative Analysis

Provides a live-benchmarked comparison of the algorithms used by the project.

The comparison includes:

- algorithm
- purpose
- key size
- measured performance
- known attacks
- real-world usage

### 4. Experiments

Each cryptographic requirement can be executed independently.

Available experiments include:

```text
AES vs 3-DES Timing
        ↓
Avalanche Effect
        ↓
ECB vs CBC
        ↓
RSA Hybrid Encryption
        ↓
Diffie-Hellman
        ↓
MITM Attack
        ↓
MITM Mitigation
        ↓
Tamper Detection
        ↓
Digital Signatures
        ↓
Certificates
        ↓
Kerberos
```

### 5. Real-World Mapping

The implemented concepts are mapped to systems and protocols they resemble in practical security architecture:

| Project Concept | Real-World Analogy |
|---|---|
| AES encryption | TLS / PGP symmetric encryption |
| RSA key protection | Hybrid encryption systems |
| Digital signatures | TLS / PGP / signed data |
| Certificates | TLS certificate infrastructure |
| Diffie-Hellman | TLS / VPN key exchange |
| Kerberos | Enterprise authentication / SSO |
| Secure TCP transfer | Network communication channel |

These mappings explain the relationship between the educational implementation and real-world security systems.

### 6. Packet Capture Evidence

The dashboard accepts a real Wireshark capture.

Supported formats:

```text
.pcap
.pcapng
```

The backend parses the capture and displays packet-level information such as:

- packet count
- protocol
- source
- destination
- port
- timestamp

The dashboard also explains what an eavesdropper can and cannot observe.

---

## Running the Dashboard

Two processes are required.

### Terminal 1: Backend

From the project root:

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Terminal 2: Frontend

```bash
cd frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

---

## Running the Secure Pipeline Standalone

The Sender and Receiver can also be executed as separate processes.

### Terminal 1: Receiver

```bash
python -m pipeline.receiver --host 127.0.0.1 --port 9443
```

### Terminal 2: Sender

```bash
python -m pipeline.sender \
    --host 127.0.0.1 \
    --port 9443 \
    --file data/samples/sample_document.txt
```

This mode is particularly useful for demonstrating an actual two-process communication flow and collecting Wireshark packet evidence.

### Two-Machine Demonstration

For communication between two machines on the same LAN:

Receiver:

```bash
python -m pipeline.receiver --host 0.0.0.0 --port 9443
```

Sender:

```bash
python -m pipeline.sender \
    --host <RECEIVER-LAN-IP> \
    --port 9443 \
    --file data/samples/sample_document.txt
```

The receiver machine must be reachable on the selected port.

---

## Running the Experiments

Each experiment can be executed independently.

### AES vs 3-DES Timing

```bash
python -m experiments.exp_aes_3des_timing
```

### Avalanche Effect

```bash
python -m experiments.exp_avalanche
```

### ECB vs CBC

```bash
python -m experiments.exp_ecb_vs_cbc
```

The ECB/CBC experiment additionally generates BMP images for visual comparison.

### RSA Hybrid Encryption

```bash
python -m experiments.exp_hybrid_rsa
```

### Diffie-Hellman Shared Secret

```bash
python -m experiments.exp_dh_shared_secret
```

### Diffie-Hellman MITM

```bash
python -m experiments.exp_mitm_dh
```

### Tamper Detection

```bash
python -m experiments.exp_tamper_detection
```

### Digital Signature

```bash
python -m experiments.exp_signature
```

### Certificate

```bash
python -m experiments.exp_certificate
```

### Kerberos

```bash
python -m experiments.exp_kerberos
```

Each experiment prints a JSON result to stdout and stores its generated output under:

```text
data/runs/experiments/
```

---

## Packet Capture & Wireshark Evidence

The project supports genuine packet-level evidence rather than fabricated network output.

A typical workflow is:

```text
Start Receiver
      ↓
Start Wireshark Capture
      ↓
Start Sender
      ↓
Transfer File
      ↓
Stop Capture
      ↓
Save .pcap / .pcapng
      ↓
Capture Wireshark Screenshot
      ↓
Upload Evidence
      ↓
Backend Parses Capture
      ↓
Dashboard Displays Analysis
```

The complete procedure is documented in:

```text
docs/packet-analysis.md
```

The packet capture demonstrates an important distinction:

**network metadata can remain visible even when the actual file contents are cryptographically protected.**

---

## Testing

The project includes a pytest suite covering the cryptographic primitives, experiments, packet parsing, secure envelope, and complete network transfer.

Run:

```bash
python -m pytest tests/ -v
```

The test suite contains **40 tests** covering areas including:

- AES round trips
- DES / 3-DES round trips
- avalanche-effect bounds
- ECB vs CBC behavior
- RSA-OAEP
- RSA-PSS signatures
- signature failure after tampering
- Diffie-Hellman
- MITM attack
- MITM mitigation
- certificate creation
- certificate verification
- certificate tampering
- certificate expiry
- Kerberos exchange
- pcap parsing
- pcapng parsing
- secure-envelope round trips
- tamper detection

There is also an end-to-end integration test that runs an actual Sender and Receiver over a real TCP socket and verifies that the received file matches the original byte-for-byte.

---

## Data Storage

Generated experiment and execution data is stored separately from the source code.

```text
data/
├── samples/
│   └── bundled sample files
│
└── runs/
    └── generated experiment outputs

evidence/
└── user-supplied Wireshark captures and screenshots
```

Generated run history is intended to remain outside the source-controlled project data where appropriate.

---

## Security

The project separates the responsibilities of its cryptographic components rather than relying on a single algorithm.

### Confidentiality

Provided by:

```text
AES-128-CBC
```

The file contents are encrypted before transmission.

### Key Protection

Provided by:

```text
RSA-OAEP
```

The AES session key is protected using public-key encryption.

### Integrity

Provided by:

```text
SHA-256
```

The Receiver can detect changes to the protected data.

### Authentication / Digital Signature

Provided by:

```text
RSA-PSS
```

The Receiver can verify that the signature matches the signed data and public key.

### Certificate Verification

Provided through the self-signed X.509-style certificate mechanism.

### Network Security Analysis

Real TCP traffic can be captured and inspected to demonstrate the difference between:

```text
Observable Network Metadata
            vs.
Protected File Contents
```

---

## Design Principles

### Transparency

Every major cryptographic operation is exposed through the dashboard and corresponding experiments.

### Real Cryptography

Cryptographic values are generated using actual library implementations rather than predefined outputs.

### Separation of Responsibilities

Each primitive has a specific role:

```text
AES       → Confidentiality
RSA-OAEP  → Key Protection
SHA-256   → Integrity
RSA-PSS   → Digital Signature
Certificate → Identity / Verification
TCP       → Transport
```

### Experiment-Driven Learning

Each important cryptographic concept has an independent experiment that demonstrates its behavior.

### Reproducible Evidence

Experiment results are saved under `data/runs/`, while real network captures are stored separately under `evidence/`.

### End-to-End Verification

The final test is not merely whether encryption succeeds. The complete system verifies that the Receiver obtains the same file as the Sender originally provided.

---

## Real-World Mapping

The project is intentionally designed around concepts found in established security systems.

| Implemented Layer | Related Real-World Technology |
|---|---|
| AES symmetric encryption | TLS, PGP |
| RSA hybrid encryption | Hybrid encryption systems |
| RSA-PSS signatures | Digital signing systems |
| X.509-style certificates | TLS / PKI |
| Diffie-Hellman | TLS, VPN |
| Kerberos | Enterprise SSO |
| TCP communication | Network transport |

The project demonstrates the underlying principles without claiming to implement the complete production protocol stacks.

---

## Documentation

The repository contains dedicated documentation for each major part of the system.

| File | Contents |
|---|---|
| `docs/architecture.md` | Component diagram and pipeline sequence |
| `docs/cryptography-concepts.md` | What each primitive does and why |
| `docs/pipeline.md` | Stage-by-stage pipeline and failure modes |
| `docs/experiments.md` | What each experiment proves and how to interpret results |
| `docs/packet-analysis.md` | Packet-capture procedure and parser output |
| `docs/real-world-mapping.md` | Mapping to TLS, PGP, SSH/VPN, and enterprise authentication |
| `docs/viva-preparation.md` | Anticipated viva questions and short answers |
| `docs/CIPAT-requirement-matrix.md` | Assignment requirement → implementation → dashboard → evidence |

---

## CIPAT Requirement Mapping

The project maintains a dedicated requirement matrix:

```text
docs/CIPAT-requirement-matrix.md
```

The matrix connects each assignment requirement with:

```text
Requirement
    ↓
Implementation File
    ↓
Experiment
    ↓
Dashboard Page
    ↓
Evidence
```

This makes it possible to trace an academic requirement directly to the corresponding implementation and demonstration.

---

## Project Status

The project is designed as a complete working cryptography demonstration platform containing:

- real cryptographic primitives
- real Sender / Receiver processes
- real TCP communication
- independent cryptographic experiments
- attack and mitigation demonstrations
- packet-capture analysis
- automated tests
- a FastAPI backend
- a React + Vite frontend
- supporting technical documentation

RSA-2048 key generation can take approximately **0.6–4 seconds** on the development machine, compared with sub-200 ms generation on faster hardware. The pipeline and experiments therefore use generous timeouts where required.

The platform is intended for **cryptography education, CIPAT requirement demonstration, security analysis, experimentation, and viva preparation** rather than production deployment.
