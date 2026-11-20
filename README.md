# QSafe: Quantum-Safe Local Storage Engine

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![NIST PQC](https://img.shields.io/badge/NIST%20FIPS%20203-ML--KEM--768-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, memory-safe, post-quantum encrypted storage vault designed to run locally on any machine without external servers or cloud dependencies.

Built in pure Rust, **QSafe** defends local backups, containers, and sensitive data against **Harvest Now, Decrypt Later (HNDL)** attacks and future Cryptanalytically Relevant Quantum Computers (CRQCs).

---

## 📚 Documentation & Specifications

Detailed architectural documents, roadmap plans, and AI prompts are located in the [`docs/`](docs/) directory:
- 📖 [**docs/SUMMARY.md**](docs/SUMMARY.md): Complete technical summary, cryptographic threat model, benchmarks, and binary `.qsafe` format specification.
- 🗺️ [**docs/FUTURE_WORK.md**](docs/FUTURE_WORK.md): Roadmap for virtual filesystem mounting (WinFsp/FUSE), TPM 2.0 PCR sealing, ML-DSA-87 signatures, and Shamir threshold secret sharing.
- 🤖 [**docs/AI_AGENT_PROMPT.md**](docs/AI_AGENT_PROMPT.md): Production instruction prompt for future AI models and autonomous agents to maintain and extend this system with identical cryptographic rigor.

---

## 🛡️ Cryptographic Architecture

```
                                      +------------------------------------+
                                      |      User Master Passphrase        |
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |  Argon2id (m=64MB, t=3, p=4)       |
                                      +-----------------+------------------+
                                                        |
                                                        v Password KEK (256-bit)
+-----------------------+              +----------------+------------------+
| Ephemeral X25519 DH   |              |     HKDF-SHA256 Combiner          |<--- Master KEK
+-----------+-----------+              +----------------+------------------+
            |                                           |
+-----------v-----------+                               v
| FIPS 203 ML-KEM-768   |-----------> Dual KEK -------->+
+-----------------------+   (Asymmetric Envelope)       |
                                                        v
                                       +----------------+------------------+
                                       | Ephemeral DEK (XChaCha20-Poly1305)|
                                       +----------------+------------------+
                                                        |
                                                        v
                                       +-----------------------------------+
                                       | STREAM Chunked AEAD Engine (64KB) |
                                       +-----------------------------------+
```

### Defense-in-Depth Primitives:
- **Post-Quantum Key Encapsulation:** NIST **FIPS 203 ML-KEM-768** (CRYSTALS-Kyber, Module-LWE).
- **Classical Asymmetric Hardening:** **X25519** ECDH. Breaking the hybrid envelope requires breaking both Module-SVP and Elliptic Curve Discrete Logarithm simultaneously.
- **Payload AEAD:** **XChaCha20-Poly1305** (256-bit key, 192-bit extended nonce, 128-bit quantum security against Grover's algorithm) or **AES-256-GCM**.
- **Memory-Hard KDF:** **Argon2id** (64 MB memory cost, 3 iterations, 4 lanes) to neutralize GPU/ASIC clusters and quantum superposition attacks.
- **Streaming AEAD Chunking:** Rogaway $\text{OAE}_2$ STREAM construction (64 KB chunks) with constant $O(1)$ memory usage and cryptographically enforced reordering, truncation, and tamper detection.
- **Memory Hygiene:** Zeroization of key material on drop (`zeroize`) and memory page locking (`VirtualLock` on Windows / `mlock` on Unix) to prevent swap extraction.

---

## 🚀 Installation & Build

```bash
git clone https://github.com/your-org/quantum_safe.git
cd quantum_safe
cargo build --release
```

The compiled standalone binary will be located at `target/release/qsafe.exe` (Windows) or `target/release/qsafe` (Linux/macOS).

---

## 💻 CLI Usage Guide

### 1. Generate a Post-Quantum Hybrid Keypair
Generate a matching public key (`id_qsafe.pub`) and password-encrypted private key (`id_qsafe.key`):
```bash
qsafe keygen --out id_qsafe --password
```

### 2. Encrypt a File
Encrypt sensitive documents into a tamper-evident `.qsafe` container:
```bash
# Using recipient's public key:
qsafe encrypt --input financial_records.zip --output financial_records.qsafe --key id_qsafe.pub

# Using password + hybrid key with AES-256-GCM:
qsafe encrypt --input database.sqlite --output database.qsafe --key id_qsafe.pub --password --cipher aes256
```

### 3. Decrypt a File
Decrypt with automatic tamper-checking and cryptographic tag verification:
```bash
qsafe decrypt --input financial_records.qsafe --output financial_records_decrypted.zip --key id_qsafe.key
```

### 4. Verify Integrity (Without Decrypting to Disk)
Audit and verify the authenticity of all STREAM chunks and headers:
```bash
qsafe verify --input database.qsafe --key id_qsafe.key
```

### 5. Inspect Container Cryptographic Metadata
View cipher suites, KDF parameters, and quantum public keys embedded in the header:
```bash
qsafe info --input financial_records.qsafe
```

### 6. Run On-Device Benchmark
Measure post-quantum key encapsulation latency and streaming encryption throughput:
```bash
qsafe bench
```

---

## 🔒 Security Audit & Guarantees

| Attack Vector | Legacy Vault (AES-CBC / RSA) | QSafe Vault |
| :--- | :--- | :--- |
| **Shor's Algorithm (CRQC)** | Broken ($O(\log^3 N)$) | **Mathematically Immune** (Module-LWE has no abelian periodicity) |
| **Grover's Algorithm (Quantum Search)** | Halved to vulnerable levels | **$\ge$ 128 bits post-quantum security** ($3.4 \times 10^{38}$ operations) |
| **Harvest Now, Decrypt Later (HNDL)** | Vulnerable | **Safe for 50+ years** |
| **Cold Boot / Memory Dump** | Plaintext in swap file | **Memory locked (`VirtualLock`), Zeroized on drop** |
| **Chunk Tampering / Truncation** | Undetected until decryption | **Instant verification per 64KB chunk tag** |
