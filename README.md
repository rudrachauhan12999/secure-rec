# SECURE-REC — Secure File Exchange & Cryptographic Analysis Platform

An educational Information & Security (CIPAT) project. It demonstrates 12 core
cryptographic tasks one by one and combines them into an end-to-end secure file
transfer. It is a Python desktop application with a Tkinter GUI. No web frontend,
database or cloud service is involved.

> **Educational use only.** This project shows how the mechanisms work and how they
> fail. It is **not** production-grade security software; see
> [Limitations](#17-limitations).

---

## 1. Problem statement

Sending files between two parties raises several separate problems. The content
must stay secret, both sides need a shared key, the receiver must be able to detect
modification, and the receiver must know who really sent the file. Each problem
needs a different mechanism, and each mechanism has its own failure modes: ECB
pattern leakage, man-in-the-middle attacks on unauthenticated Diffie-Hellman,
silently modified CBC ciphertext, untrusted keys, and more.

## 2. Project objective

- Implement and demonstrate the 12 required tasks, each with visible, saved evidence.
- Combine them into one **integrated sender → receiver pipeline** that accepts any file
  and proves `original bytes == recovered bytes`.
- Demonstrate attacks and their mitigations (avalanche effect, ECB leakage, MITM, tampering).
- Produce reproducible, clearly labelled outputs for the academic report.

## 3. Features

- Works on **any file type** (text, PDF, images, arbitrary binary): all encryption operates on raw bytes.
- The **Kaggle student dataset** is the default demonstration input.
- The 12 tasks, each runnable on its own from the CLI or the GUI.
- An **integrated secure pipeline**: AES-128-CBC, RSA-OAEP key protection, RSA-PSS signature,
  X.509 certificate with pinned trust, simulated transfer, verification and recovery.
- A **tamper mode** that modifies the transmitted package and shows which check catches it.
- A **local TCP sender/receiver** for real Wireshark captures.
- A **Tkinter GUI** that only orchestrates. All cryptography lives in `core/`, `tasks/` and `pipeline/`.
- Every run writes `report.txt` and `report.json` plus its evidence files.
- 189 automated tests.

## 4. Architecture

```
               +--------------------------------------------+
               |  app/  (Tkinter GUI - orchestration only)  |
               |  task_registry -> presenter -> components  |
               +--------------------+-----------------------+
                                    | calls run(), receives TaskResult
            +-----------------------+------------------------+
            v                                                v
+-------------------------+                   +------------------------------+
| tasks/  (Tasks 1-12,    |                   | pipeline/  (integrated flow) |
| one module per task)    |                   | sender -> package -> receiver|
+-----------+-------------+                   | network_demo (TCP)           |
            |                                 +--------------+---------------+
            +---------------------+------------------------- +
                                  v
+-------------------------------------------------------------------------+
| core/  crypto_utils (AES/3-DES/GCM/RSA-OAEP), hybrid, signatures (PSS),  |
|        diffie_hellman, certificates (OpenSSL), hashing, key_manager,     |
|        file_handler, validators, results (TaskResult), config            |
+-------------------------------------------------------------------------+
               PyCryptodome  |  hashlib  |  OpenSSL CLI  |  Pillow  |  matplotlib
```

- Every task and the pipeline return the same `TaskResult` object
  (status, summary, details, artifacts, data). It can be saved as `report.txt`/`report.json`.
- The GUI never implements cryptography. A test scans `app/` and fails if it imports any
  crypto library or crypto module.
- Actual cryptographic operations come from established libraries: PyCryptodome, Python's
  `hashlib` and the OpenSSL CLI. Nothing is implemented from scratch, apart from the
  Diffie-Hellman modular arithmetic (Python `pow`), which is written out for teaching.

## 5. Technology stack

| Component | Used for |
|---|---|
| Python 3.11+ | application language |
| Tkinter / ttk | desktop GUI (bundled with python.org installers) |
| PyCryptodome | AES (CBC/ECB/GCM), 3-DES, RSA (OAEP, PSS), HKDF |
| hashlib | SHA-256, PBKDF2 |
| OpenSSL (CLI) | X.509 certificate generation, inspection and verification |
| Pillow | image handling (Task 3), GUI thumbnails |
| matplotlib | Task 4 benchmark chart |
| pytest | test suite |
| Wireshark + Npcap | optional packet capture of the network demo |

## 6. Project structure

```
app/
  main.py                   GUI entry point (python -m app.main)
  gui/app.py                main window: input, worker thread, result display
  gui/dashboard.py          file panel, pipeline buttons, 12 task buttons
  gui/components/           file_panel, result_panel, status_bar
  gui/task_registry.py      button -> existing task/pipeline run() (no Tk, no crypto)
  gui/presenter.py          TaskResult -> display model (no Tk, no crypto)
  gui/worker.py             background thread + queue for long operations
  gui/file_opener.py        opens outputs only inside outputs/ and benchmarks/
core/                       shared cryptographic and utility modules
tasks/task01..task12_*.py   the 12 individual demonstrations
pipeline/
  secure_pipeline.py        integrated sender -> receiver pipeline (+ --tamper)
  sender.py / receiver.py   the two sides; receiver stops at the first failed check
  package.py                transfer-package format and the exact signed structure
  network_demo.py           local TCP sender/receiver for Wireshark
data/student_records.txt    default dataset
tests/                      pytest suite
outputs/                    generated evidence (git-ignored)
keys/                       generated private keys (git-ignored)
benchmarks/                 generated benchmark inputs (git-ignored data/)
wireshark/, screenshots/    places for captures and report screenshots
```

## 7. Installation

Requires **Python 3.11+** (with Tkinter) and **OpenSSL** on `PATH`. OpenSSL is needed for
Task 11 and the integrated pipeline.

```bash
git clone https://github.com/rudrachauhan12999/secure-file-exchange-crypto-platform.git
cd secure-file-exchange-crypto-platform
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
openssl version            # should print a version
```

On Windows, Git for Windows already ships OpenSSL. SECURE-REC searches `PATH`, the
`OPENSSL_BIN` environment variable, and the usual Git/OpenSSL install folders. If
OpenSSL is missing, Task 11 and the pipeline report a clear ERROR; everything else works.

## 8. Running the application

**GUI**

```bash
python -m app.main
```

**Individual tasks (CLI).** Each task runs on its own. Without a file argument the
student dataset is used, and results go to `outputs/taskNN/`.

```bash
python -m tasks.task01_symmetric   [file]
python -m tasks.task02_avalanche   [file]
python -m tasks.task03_ecb_cbc     <image> | --demo     # --demo = generated flat-colour image
python -m tasks.task04_performance                      # generated benchmark files
python -m tasks.task05_hybrid      [file]
python -m tasks.task06_diffie_hellman                   # no file needed
python -m tasks.task07_mitm        [file]
python -m tasks.task08_sha256      [file] [--received other_file]
python -m tasks.task09_tampering   [file]
python -m tasks.task10_signature   [file]
python -m tasks.task11_certificate [file]
python -m tasks.task12_kerberos                         # no file needed
```

**Integrated pipeline**

```bash
python -m pipeline.secure_pipeline data/student_records.txt
python -m pipeline.secure_pipeline data/student_records.txt --tamper
python -m pipeline.secure_pipeline <file> --tamper wrapped-key|signature|certificate|impersonation
```

All commands accept `--out <dir>` to write somewhere other than `outputs/`.

## 9. GUI usage

1. **Selected File.** The student dataset is pre-selected. Use **Select File...** for any other
   file, **Use Sample Dataset** to go back to it, or **Clear** to remove the selection. The panel
   shows name, type, size, SHA-256, and whether the file is an image.
2. **Integrated Secure Pipeline**
   - **RUN COMPLETE SECURE PIPELINE** runs the normal transfer.
   - **RUN PIPELINE WITH TAMPERING** runs the `--tamper` mode (ciphertext modified in transit).

   The result shows a ✓ / ✗ / – checklist of every stage, read from the pipeline's result, and
   the final verdict: `SECURE TRANSFER SUCCESSFUL` or `SECURE TRANSFER REJECTED` with the reason.
3. **Individual Tasks.** Twelve buttons call the existing task modules.
   - Task 3 on a non-image shows `NOT APPLICABLE — Image input required`.
   - Task 4 always uses its generated benchmark files.
   - Tasks 6 and 12 need no file.
4. **Result.** Shows the status, the task's summary lines, and a task-specific view where useful:
   the pipeline stages, the Task 4 benchmark table and chart thumbnail, the Task 3 comparison
   thumbnail, and the Task 7/12 transcripts. Buttons open the full report, the output folder, and
   task artifacts: images, chart, CSV, certificate information, transcripts. Double-click an
   artifact to open it. Only files inside `outputs/` and `benchmarks/` can be opened.
5. Long operations run on a background thread. Buttons are disabled and a progress indicator runs
   until the job finishes. Errors appear as an `ERROR` result instead of crashing the window.

## 10. The 12 tasks

| # | Task | What it does and what it shows |
|---|---|---|
| 1 | **Symmetric encryption** | AES-128-CBC and 3-key 3-DES-CBC (PKCS#7) on the selected file's bytes. Saves `IV‖ciphertext` and the decrypted file, then checks byte equality. Keys come from the OS CSPRNG, stay in memory, and appear only as fingerprints; IVs are random and public. |
| 2 | **Avalanche effect** | Flips exactly one plaintext bit and encrypts both versions with the **same key and IV** (a controlled experiment; otherwise the IV change alone hides the effect). Measures changed ciphertext bits for the whole file (CBC), one raw AES block, and all 128 bit positions (about 50 %). |
| 3 | **ECB vs CBC** | **Requires an image.** Encrypts the raw RGB pixels with AES-ECB and AES-CBC. Width and height are kept as a clear "header" and outputs are lossless PNG. Shows the patterns ECB leaks, counts repeated 16-byte blocks, and saves a side-by-side comparison. Non-images give `NOT APPLICABLE`. |
| 4 | **AES vs 3-DES performance** | Uses **controlled benchmark files** (1 KB / 10 KB / 100 KB from a fixed seed), not the selected file. Records the median of 200 timed runs for encryption and decryption, and saves a table, CSV/JSON and a chart. |
| 5 | **RSA + AES hybrid** | RSA-2048 key pair; random AES-128 session key; the file is encrypted with AES-CBC and the key wrapped with RSA-OAEP-SHA256. The receiver unwraps and decrypts; byte equality is checked, and a wrong RSA key is shown to fail. RSA never encrypts the file itself. |
| 6 | **Diffie-Hellman** | RFC 3526 2048-bit MODP group, secure random exponents, and validation of received public values. Both sides derive the same secret, turned into a key with HKDF-SHA256 and used for an AES round trip. Private values are shown only as `<hidden>`. |
| 7 | **DH MITM attack** | *Intentionally simulated, entirely in memory.* The attacker swaps public values and ends up with one key for each victim, then reads and alters traffic. Mitigation: DH values signed with RSA-PSS identity keys. Both attack variants (forwarding the old signature, or re-signing with its own key) are detected. |
| 8 | **SHA-256 integrity** | Hashes the original and the received file (by default after an AES encrypt/decrypt transfer, or any file via `--received`) and reports `INTEGRITY VERIFIED` or not. Writes `sha256sums.txt`. |
| 9 | **Tampering detection** | Modifies the IV (a silent targeted CBC bit-flip), a ciphertext byte, and the received file. Each shows the original hash, received hash, `MATCH: FALSE` and `TAMPERING DETECTED`; the genuine case verifies. Data is never repaired. |
| 10 | **Digital signature** | RSA-PSS/SHA-256. The original file gives `VALID`; a modified file, the wrong public key, or an altered signature give `INVALID`. Includes a confidentiality / integrity / authenticity table. |
| 11 | **X.509 certificate** | OpenSSL builds a **self-signed**, educational certificate (Subject, Issuer, Public Key, Validity, Signature) and verifies it with `-check_ss_sig`. A certificate with a changed subject and one with a changed signature are both rejected; the certificate's key verifies a file signature. The private key goes only to `keys/task11/`. |
| 12 | **Kerberos** | An **educational simulation**, not a real server. Flow: Client → AS (pre-authentication) → TGT → TGS → service ticket → application server, then mutual authentication. Tickets are sealed with AES-GCM and the client key comes from PBKDF2. Wrong password, forged TGT, stolen ticket, replay and expired ticket are all rejected. A simulated clock makes it reproducible. |

## 11. Integrated secure pipeline

```
SETUP (out of band)  receiver RSA-2048 key pair; sender RSA-2048 key + self-signed
                     certificate; receiver PINS the certificate's SHA-256 fingerprint
SENDER               read file -> SHA-256 -> random AES-128 session key
                     -> AES-128-CBC(file) + AES-128-CBC(manifest: name/type/size/SHA-256)
                     -> RSA-OAEP-SHA256(session key) -> RSA-PSS-SHA256 signature
TRANSFER             only sender/transfer_package.srpkg (JSON) is "sent"
RECEIVER             1 package format        5 RSA key recovery
(stops at first      2 certificate (OpenSSL)  6 AES decryption
 failure)            3 sender identity (pin)  7 SHA-256 integrity
                     4 digital signature      + byte-for-byte comparison with original
```

- **Signed structure** (`pipeline/package.py`): canonical JSON containing the header, the
  certificate fingerprint, the IVs, and SHA-256 hashes of the wrapped key and both ciphertexts.
  Every transmitted field is covered, so a modified package is rejected **before** decryption.
  The exact structure of each run is saved as `sender/signed_structure.json`.
- **The package never contains** plaintext, the raw session key or any private key. File name,
  size and SHA-256 travel inside the encrypted manifest.
- **Trust:** the certificate is self-signed, so it gives **no real-world CA trust**. It is
  accepted only because its fingerprint was pinned beforehand. `--tamper impersonation` shows
  why: the attacker's own valid self-signed certificate is rejected at the identity stage.
- **Tamper targets and where they are caught:**

  | Target | Caught at |
  |---|---|
  | `ciphertext` (default), `wrapped-key`, `signature` | Digital signature |
  | `certificate` | Certificate verification |
  | `impersonation` | Sender identity |

  In tamper mode the run reports **PASS** when the modification is detected at the expected stage.

## 12. Network / Wireshark demonstration

`pipeline/network_demo.py` sends a previously created package over **plain local TCP**. This is
intentional: the capture shows that the application-layer protection alone keeps the content
confidential.

```bash
python -m pipeline.secure_pipeline data/student_records.txt --tamper   # genuine + tampered package, same keys
python -m pipeline.network_demo --server --count 2                     # terminal A (127.0.0.1:5055)
python -m pipeline.network_demo --client outputs/integrated_pipeline/sender/transfer_package.srpkg          # ACCEPTED
python -m pipeline.network_demo --client outputs/integrated_pipeline/tamper/tampered_transfer_package.srpkg  # REJECTED
```

Each pipeline run creates new keys, so restart the server after re-running the pipeline.

**Protocol**
- Client → Server: `"SRPKG1" | uint64 length | package JSON`
- Server → Client: `"SRACK1" | uint64 length | {"status", "failed_stage", "received_bytes", "package_sha256"}`

The reply contains a hash of the *package*, never of the file. The server reads its receiver key
and trust store from `keys/integrated_pipeline/`, runs the same receiver checks, and saves an
accepted file to `outputs/integrated_pipeline/network_received/`.

**Capturing with Wireshark (Windows)**
1. Install Wireshark with **Npcap**, ticking *"Support loopback traffic capture"*.
2. Start a capture on **"Adapter for loopback traffic capture"**. On Linux/macOS, use the `lo`/`lo0` interface.
3. Display filter: `tcp.port == 5055`.
4. Run the server and client commands above, then use *Follow → TCP Stream*.
5. Save the capture in `wireshark/` (`*.pcap`/`*.pcapng` are git-ignored).

**What an eavesdropper can and cannot see**
- *Can see:* IP addresses and ports, timing, sizes, the header (algorithms, sender name,
  receiver-key fingerprint), the public certificate, base64 ciphertext and signature, and the
  ACCEPTED/REJECTED reply.
- *Cannot see:* file contents, file name, file SHA-256, the session key, or any private key.

No packet captures are included in the repository; you make your own. The tests check the actual
bytes sent over the socket using a capturing relay.

## 13. Dataset / source

- **Kaggle, "Student Performance Data Set"** (dskagglemt), originally from the UCI Machine Learning
  Repository (P. Cortez & A. Silva, 2008): <https://www.kaggle.com/datasets/dskagglemt/student-performance-data-set>.
- Stored unmodified as `data/student_records.txt` (fixed-width text, 395 records, 68,776 bytes).
- It is the **default** input only. Every task that takes a file, and the pipeline, work with
  any file the user selects.

## 14. Security considerations

- **Randomness:** keys, IVs, nonces and DH exponents come from the OS CSPRNG
  (`Crypto.Random`, `secrets`). No key is hard-coded. IVs are reused only inside controlled
  measurements: the Task 2 avalanche experiment (explained in its report) and the Task 4 timing
  loop, where one random key and IV per cipher are reused across the timed repetitions.
- **Secrets are never displayed or saved in outputs.** Symmetric keys appear only as truncated
  SHA-256 fingerprints; DH private values as `<hidden>`; the Kerberos password is random at runtime
  and never written. Tests scan all generated outputs, network traffic and GUI text for
  private-key and session-key material.
- **Private RSA keys** are written only where a later step needs them, and only under the
  git-ignored `keys/` folder:
  - `keys/task11/`, because OpenSSL needs the key file to self-sign;
  - `keys/integrated_pipeline/`: the sender key for the same reason, and the receiver key for the
    network demo.

  These key files are stored **unencrypted**.
- **Confidentiality vs integrity vs authenticity:**
  - AES/RSA-OAEP give confidentiality.
  - SHA-256 detects change, but only if the reference hash is trustworthy.
  - RSA-PSS signatures and the pinned certificate give authenticity.
  - AES-GCM (used for Kerberos tickets) gives confidentiality and integrity together.
- **CBC is malleable** (Task 9 shows a silent targeted bit-flip). The pipeline therefore verifies
  the signature before decrypting anything.
- **The GUI** can only open files inside `outputs/` and `benchmarks/`, never `keys/`.
  Received file names are stripped to their base name, so they cannot escape the output folder.

## 15. Output structure

```
outputs/
  task01/ ... task12/          per-task evidence + report.txt + report.json
    task02/  per_block_bit_differences.csv, single_block_bit_sweep.csv
    task03/  original_rgb.png, encrypted_ecb.png, encrypted_cbc.png, comparison_original_ecb_cbc.png
    task04/  benchmark_results.csv/.json, benchmark_table.txt, benchmark_chart.png
    task05/  receiver_public_key.pem, transfer/<file>.hybrid, recovered_<file>
    task06/  public_transcript.json          task07/  transcript.txt
    task08/  sha256sums.txt                  task09/  tamper_log.csv, tampered .enc files
    task10/  sender_public_key.pem, <file>.sig, modified_<file>
    task11/  sender_certificate.pem/.der, certificate_info.txt, tampered certificates
    task12/  transcript.txt
  integrated_pipeline/
    report.txt, report.json
    sender/    transfer_package.srpkg, signed_structure.json, sender_certificate.pem
    receiver/  receiver_public_key.pem, received_sender_certificate.pem, recovered_<file>
    tamper/    tampered_transfer_package.srpkg (+ attacker_certificate.pem)
    network_received/  recovered_<file> from the network demo
keys/        task11/, integrated_pipeline/   (private keys, trust store - git-ignored)
benchmarks/data/   bench_1KB.bin, bench_10KB.bin, bench_100KB.bin (git-ignored)
```

## 16. Testing

```bash
python -m pytest
```

The suite has 189 tests and takes about 1–2 minutes. It covers:
- round trips for every cipher and task on text, binary, PDF-like, PNG and JPEG inputs;
- the positive and negative cases for every task (tampering, wrong keys, forged or expired tickets,
  certificate tampering);
- the integrated pipeline and all tamper targets;
- the TCP demo, including a capturing relay that confirms no plaintext is transmitted;
- the GUI: backend adapter, presenter, safe file opening, and a hidden Tk window driving real button
  actions;
- a static check that the GUI contains no cryptography;
- scans for secrets in outputs.

Tests write only to temporary folders. OpenSSL-dependent tests are skipped if OpenSSL is not
installed.

## 17. Limitations

- **Educational scope.** Not audited and not production-grade. The DH arithmetic uses Python's
  `pow`, which is not constant-time.
- **3-DES** is included only for comparison; it is deprecated (NIST SP 800-131A).
- **Task 4 timings** depend on the machine. In this project's own runs AES was about 5× faster at
  1 KB and roughly 10–23× faster at 10–100 KB. The ratio is what matters.
- **Task 3** makes ECB leakage most visible on images with flat colours. Photographs show less.
- **Certificates.** Task 11 and the pipeline use a **self-signed certificate with pinned trust**:
  no CA chain, no revocation (CRL/OCSP).
- **Task 7** is an in-memory simulation with no real network interception. Its mitigation signs
  each DH value rather than the whole handshake transcript.
- **Task 12** is a simplified single-realm Kerberos model: no ASN.1 or network protocol, no ticket
  renewal, forwarding or cross-realm.
- **Pipeline.** No replay protection for packages. The byte-for-byte check is possible only because
  sender and receiver run in one process; a real receiver relies on the signed SHA-256.
  Files up to 200 MB are processed in memory.
- **Network demo.** Plain TCP on localhost by design, one connection at a time.
- **Private keys** in `keys/` are stored unencrypted, protected only by being git-ignored.

## 18. Academic / educational disclaimer

SECURE-REC was built for an Information & Security coursework project to teach how cryptographic
mechanisms work and how attacks against them succeed or fail. All attacks (MITM, tampering,
impersonation) are simulations against the project's own data on the local machine. Do not use
this code to protect real data, and do not use the attack demonstrations against systems you are
not authorised to test.
