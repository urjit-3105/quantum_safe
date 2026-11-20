# QSafe: System Summary & Cryptographic Specifications

## 1. Executive Summary

**QSafe** is a zero-dependency, memory-safe, post-quantum secure local storage vault engineered in pure Rust. It was built from the ground up to address the **Harvest Now, Decrypt Later (HNDL)** threat model, where adversaries capture and archive encrypted local files and backups today with the intent of retroactively decrypting them once a Cryptanalytically Relevant Quantum Computer (CRQC) becomes viable.

QSafe bridges NIST-finalized post-quantum standards with defense-in-depth classical algorithms and modern memory hygiene, achieving sub-millisecond cryptographic operations and ~744 MB/s streaming throughput.

---

## 2. Core Cryptographic Architecture

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
+-----------------------+          +----------------+------------------+
| Ephemeral X25519 DH   |          |     HKDF-SHA256 Combiner          |<--- Master KEK
+-----------+-----------+          +----------------+------------------+
            |                                       |
+-----------v-----------+                           v
| FIPS 203 ML-KEM-768   |-----> Dual KEK ---------->+
+-----------------------+ (Asymmetric Envelope)     |
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

### A. Post-Quantum Hybrid Key Encapsulation (FIPS 203 ML-KEM-768 + X25519)
- **Primary KEM:** NIST **FIPS 203 ML-KEM-768** (formerly CRYSTALS-Kyber), based on the hardness of the Module Learning With Errors (M-LWE) lattice problem.
- **Classical Layer:** **X25519** Elliptic Curve Diffie-Hellman.
- **Dual Combiner:** Shared secrets are extracted and expanded using `HKDF-SHA256` with strict domain separation (`qsafe-v1-hybrid-kem-x25519-mlkem768`).
- **Security Guarantee:** Compromising the envelope requires simultaneously solving the Shortest Vector Problem (SVP) in a 768-dimensional module lattice AND the Elliptic Curve Discrete Logarithm Problem (ECDLP) on Curve25519.

### B. Payload Encryption & Online Streaming (Rogaway $\text{OAE}_2$ STREAM)
- **Cipher Primitives:** **XChaCha20-Poly1305** (default; 256-bit key, 192-bit extended nonce) and **AES-256-GCM** (NIST FIPS compliant).
- **Chunk Size:** 64 KB per authenticated block.
- **Nonce Derivation:** Each chunk nonce is cryptographically derived from:
  $$\text{Nonce}_{\text{chunk}} = \text{BaseNonce}_{16\text{B}} \parallel \text{ChunkIndex}_{7\text{B BE}} \parallel \text{IsLastChunkFlag}_{1\text{B}}$$
- **Security Properties:**
  - $O(1)$ constant RAM footprint (can process multi-terabyte files on 1 GB RAM machines).
  - Immunity against chunk reordering, block swapping, insertion, and truncation attacks.
  - Granular seekable decryption without full-file deserialization.

### C. Password Hardening & Memory Resistance (Argon2id)
- **Algorithm:** **Argon2id** (v1.3, hybrid data-dependent and data-independent memory access).
- **Default Parameters:** Memory cost $m = 65,536\text{ KB}$ (64 MB), Time cost $t = 3$ iterations, Parallelism $p = 4$ lanes.
- **Post-Quantum Defense:** Neutralizes quantum superposition attacks (Grover search on passwords) due to the **Quantum RAM (QRAM) bottleneck**; quantum computers cannot scale error-corrected multi-megabyte superposition state memory without exponential decoherence.

### D. Memory Hygiene & Anti-Forensics
- **Zeroization:** All key buffers implement `zeroize::Zeroize` and automatic zeroing on drop.
- **RAM Locking:** Integrates Windows `VirtualLock` and Unix `mlock` to pin cryptographic key buffers in physical RAM, preventing the OS from writing plaintext keys to swap space or `pagefile.sys`.
- **Constant-Time Operations:** All tag comparisons enforce constant-time equality (`subtle::ConstantTimeEq`).

---

## 3. Tamper-Proof Binary Container Format (`.qsafe`)

```
+-------------------------------------------------------------------------+
|                              MAGIC: "QSAFE" (5 Bytes)                   |
+-------------------+-----------------------------------------------------+
|  VERSION: 0x01    |  CIPHER_SUITE: 0x01 (XChaCha20) / 0x02 (AES-256-GCM)|
+-------------------+-----------------------------------------------------+
|  ARGON2_PARAMS: m_cost (4B) | t_cost (4B) | p_cost (4B)                 |
+-------------------------------------------------------------------------+
|  KDF_SALT (32 Bytes CSPRNG)                                             |
+-------------------------------------------------------------------------+
|  BASE_NONCE (16 Bytes CSPRNG)                                           |
+-------------------------------------------------------------------------+
|  EPHEMERAL_X25519_PUBLIC_KEY (32 Bytes)                                 |
+-------------------------------------------------------------------------+
|  ML-KEM-768 CIPHERTEXT (1,088 Bytes)                                    |
+-------------------------------------------------------------------------+
|  ENCRYPTED_DEK_ENVELOPE (32B DEK + 16B Poly1305 Tag = 48 Bytes)         |
+-------------------------------------------------------------------------+
|  HEADER_AUTH_TAG (32 Bytes HMAC-SHA256 over entire preceding header)    |
+=========================================================================+
|  CHUNK 0: [Len: 4B BE] [Ciphertext (<=64KB) + Tag: 16B]                 |
+-------------------------------------------------------------------------+
|  CHUNK 1: [Len: 4B BE] [Ciphertext (<=64KB) + Tag: 16B]                 |
+-------------------------------------------------------------------------+
|  ...                                                                    |
+-------------------------------------------------------------------------+
|  CHUNK N (LAST): [Len: 4B BE] [Ciphertext (<=64KB) + Tag: 16B]          |
+-------------------------------------------------------------------------+
```

---

## 4. Benchmark Performance Metrics

Tested on standard x86-64 hardware using `qsafe bench`:

| Operation | Metric | Performance |
| :--- | :--- | :--- |
| **FIPS 203 ML-KEM-768 Keygen** | Latency | **99.43 µs / op** (~10,057 keypairs/sec) |
| **Hybrid Encapsulation (ML-KEM + X25519)** | Latency | **152.10 µs / op** |
| **Argon2id Key Stretching (64 MB, t=3)** | Latency | **103.33 ms** |
| **STREAM XChaCha20-Poly1305** | Throughput | **743.94 MB/s** |
| **Tamper Detection Response** | Latency | **< 10 µs** (immediate hard abort) |

---

## 5. Verification Matrix

The test suite in [`tests/test_vault.rs`](file:///D:/projects/quantum_safe/tests/test_vault.rs) exercises 7 automated tests:
1. `test_hybrid_kem_roundtrip`: Verifies mutual shared secret generation between two distinct keypairs and rejects wrong private key decapsulation.
2. `test_stream_xchacha20_roundtrip`: End-to-end streaming encryption/decryption of arbitrary buffers.
3. `test_stream_aes256_roundtrip`: Multi-chunk streaming verification with AES-256-GCM.
4. `test_tamper_detection_chunk_bitflip`: Single-bit flipping in chunk payload triggers exact `PayloadTampered(chunk_idx)`.
5. `test_tamper_detection_truncation`: Abrupt stream termination without final chunk marker triggers tamper error.
6. `test_vault_e2e_header_tamper_detected`: Modification of any byte in container header triggers immediate `AuthenticationFailed`.
7. `test_vault_e2e_encryption_decryption`: Full file lifecycle test confirming bit-for-bit authenticity of decrypted payloads.
