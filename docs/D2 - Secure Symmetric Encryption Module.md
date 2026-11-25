# Deliverable 2 (D2): Core Cryptographic Module Implementation

**Branch:** `feature/d2-crypto-module`

> **Note:** This document describes the D2 implementation as it exists in the `feature/d2-crypto-module` branch (single owner, binary container, D2 tests). In `main`, the module was extended in D3 (hybrid encryption, a fresh file key per file) and D5 (signed JSON container), and `tests/test_crypto.py` now contains the D3 tests.

## Overview of What Was Implemented

For **Deliverable 2**, we designed and implemented the core symmetric cryptographic engine of the **Secure Digital Document Vault**. Instead of relying on legacy unauthenticated modes (such as AES-CBC, which are vulnerable to padding oracle and ciphertext manipulation attacks), this module implements **Authenticated Encryption with Associated Data (AEAD)** using **AES-256-GCM** (Galois/Counter Mode).

The implementation is divided into two main components:
1. **`vault/crypto_module.py` (`SecureEncryptionModule`):** The cryptographic engine responsible for key generation, nonce management, authenticated file/data encryption, metadata binding, and fail-safe decryption.
2. **`tests/test_crypto.py`:** An adversarial unit test suite that validates both functional correctness and cryptographic failure modes under tampering attacks.

---

## 1. Core Cryptographic Engine (`vault/crypto_module.py`)

The `SecureEncryptionModule` class encapsulates all low-level cryptographic primitives using Python's `cryptography` library (`AESGCM`), preventing misuse of keys and nonces across the application.

### A. 256-Bit Key Generation and Validation
* **Implementation:** The module enforces the use of **256-bit (32-byte)** symmetric keys generated via a Cryptographically Secure Pseudo-Random Number Generator (**CSPRNG**).
* **How it works:** Each `SecureEncryptionModule` instance generates a fresh 256-bit key with `AESGCM.generate_key(bit_length=256)`, which internally uses the OS CSPRNG (`os.urandom`). No manual seeding or predictable generator is used. This provides $2^{256}$ keyspace security and follows NIST SP 800-38D.

### B. Dynamic Nonce Management (96-Bit CSPRNG)
* **Implementation:** Every single encryption call dynamically generates a fresh **12-byte (96-bit) random nonce** using `os.urandom(12)`.
* **How it works:** In AES-GCM, reusing a `(Key, Nonce)` pair catastrophically compromises both confidentiality (via keystream XOR recovery) and integrity (by exposing the internal GHASH authentication key). By generating a cryptographically random 96-bit nonce inside the encryption method itself—rather than requiring the caller to pass one—the implementation guarantees **semantic security**: encrypting the exact same document twice with the same key produces two completely different ciphertexts.

### C. Authenticated Encryption & Binary Packaging
* **Implementation:** The encryption logic takes the plaintext payload (or source file) and optional **Associated Authenticated Data (AAD)**, encrypts the data using AES-256 in Counter (CTR) mode, and computes a **128-bit (16-byte) Galois Message Authentication Code (GMAC/Tag)**.
* **How the output is structured:** The container is self-contained. The metadata header (AAD) is stored in clear text but authenticated, followed by the nonce and the ciphertext with its 16-byte tag:

```text
+-------------------+----------------------+------------------+------------------------+------------------+
| AAD length (4 B)  | Header / AAD (JSON)  | Nonce (12 bytes) | Ciphertext (N bytes)   | GCM Tag (16 B)   |
| big-endian        | filename, version,   | 96-bit CSPRNG    | AES-256-GCM payload    | 128-bit auth tag |
|                   | creation_timestamp   |                  |                        |                  |
+-------------------+----------------------+------------------+------------------------+------------------+
```

### D. Context Binding via Associated Authenticated Data (AAD)
* **Implementation:** Both the encryption and decryption routines accept an `aad` parameter (e.g., original filename, document ID, owner ID, or version headers).
* **How it works:** The AAD is not encrypted, but it is fed directly into the internal **GHASH** polynomial calculation that produces the 16-byte authentication tag. This cryptographically binds the file's context to its encrypted payload. If an attacker renames an encrypted file or swaps two encrypted files in the vault, the AAD check will fail during decryption even though the attacker has not modified the ciphertext itself.

### E. Fail-Safe Authenticated Decryption
* **Implementation:** During decryption, the module slices the first 12 bytes to recover the nonce and passes the remaining bytes (ciphertext + 16-byte tag) along with the expected AAD into the `AESGCM.decrypt()` verification pipeline.
* **How it works:** AES-GCM follows an **Encrypt-then-MAC** construction under the hood. When decrypting, the engine recomputes the GHASH tag over the AAD and ciphertext and performs a constant-time comparison against the attached 16-byte tag *before* releasing any plaintext. If a single bit was modified in the nonce, ciphertext, tag, or AAD—or if the wrong key is supplied—the module immediately raises an `InvalidTag` exception and aborts without writing corrupted or unverified data to disk.

---

## 2. Design Rationale: Why AES-256-GCM Was Implemented Over ChaCha20-Poly1305

As part of D2, we evaluated **AES-256-GCM** against **ChaCha20-Poly1305**:
* Both algorithms provide equivalent cryptographic strength (256-bit keys and 128-bit authentication tags) and native AEAD support.
* **AES-256-GCM** was chosen for our implementation because the target environment for the Document Vault consists of modern desktop and server processors equipped with hardware **AES-NI** (Intel/AMD) and **ARMv8 Cryptography Extensions**. Hardware acceleration allows AES-256-GCM to achieve significantly higher throughput on large local documents while eliminating software cache-timing side channels.

---

## 3. Adversarial Test Suite Implementation (`tests/test_crypto.py`)

To prove that the cryptographic implementation enforces its security guarantees, we implemented a suite of automated unit tests covering both normal execution and active tampering scenarios:

1. **Lossless Round-Trip Verification:** Encrypts sample documents and verifies that decrypting with the matching key and AAD restores the exact bit-for-bit original plaintext.
2. **Semantic Security (Nonce Uniqueness):** Encrypts the exact same document twice under the same 256-bit key and verifies that both the resulting 12-byte nonces and ciphertexts are completely distinct.
3. **Ciphertext Tampering Detection (Bit-Flip Attack):** Simulates an attacker flipping a single bit inside the encrypted payload of a vault file and asserts that the decryption routine rejects the file with an authentication error rather than returning corrupted plaintext.
4. **Metadata / AAD Tampering Detection:** Simulates an attacker attempting to spoof file metadata (providing modified AAD during decryption while keeping the key and ciphertext intact) and verifies that the GCM tag verification fails immediately.
5. **Unauthorized Key Rejection:** Attempts to decrypt a valid vault container using a newly generated 256-bit key and asserts that authentication fails safely.
6. **Ciphertext Body Tampering:** Flips one bit inside the ciphertext itself (not the tag) and asserts that decryption fails.

---

## 4. Security Decisions

### Why AEAD instead of encryption + hash?
A plain hash (e.g., `SHA-256(ciphertext)`) uses no key, so an attacker who modifies the ciphertext can simply recompute the hash and the change goes undetected. Building integrity manually (encryption + separate MAC) is possible but error-prone: wrong order (MAC-then-encrypt), forgetting to authenticate the IV or metadata, using the same key for both, or comparing tags in non-constant time have all led to real attacks (e.g., padding oracle attacks on CBC). AEAD (AES-GCM) provides confidentiality, integrity and authentication of the ciphertext **and** the metadata (AAD) in a single, standardized, well-analyzed primitive, and refuses to return any plaintext if the tag does not verify.

### What happens if a nonce repeats?
In AES-GCM, the nonce determines the CTR keystream. If two files are encrypted with the same key and the same nonce:
- **Confidentiality breaks:** both ciphertexts share the same keystream, so `C1 XOR C2 = P1 XOR P2`. Knowing (or guessing) part of one file reveals the other.
- **Integrity breaks:** the attacker can recover the GHASH authentication key `H` and then forge valid tags for arbitrary modified ciphertexts.

To prevent this, every encryption generates a random 96-bit nonce with `os.urandom(12)` inside the module (the caller cannot supply one), and each file uses a fresh 256-bit key, so the (key, nonce) pair never repeats in practice.

### What attacker are we defending against?
An attacker who has **full read and write access to the encrypted container** (stolen disk, compromised cloud storage, or an untrusted network channel) but **does not have the file key**. This attacker may:
- Read the container and try to learn its contents → prevented by AES-256-GCM confidentiality.
- Flip bits in the ciphertext, nonce or tag → detected by the GCM tag (`InvalidTag` → `ValueError`).
- Rename the file or modify the metadata (filename, version, timestamp) → detected because the header is authenticated as AAD.
- Try to decrypt with a different key → authentication fails and no plaintext is released.

Out of scope for D2: an attacker who has stolen the key or compromised the owner's machine, and sharing with other users (addressed in D3).

---

## 5. Random Nonces: Probability of Collision and Per-Key Usage Limits

AES-GCM nonces in this project are **random** 96-bit values (`os.urandom(12)`), not counters. Their uniqueness is therefore **probabilistic**, not guaranteed:

* By the birthday bound, after encrypting *q* messages with the **same key**, the probability that two of them share a nonce is approximately **q² / 2⁹⁷**.
* NIST SP 800-38D (§8.3) requires that the probability of a repeated IV stays below 2⁻³², which limits random 96-bit IVs to at most **2³² encryptions per key**. With q = 2³², the collision probability is about 2⁶⁴ / 2⁹⁷ = 2⁻³³.
* Each single message is also limited to 2³⁹ − 256 bits (about **64 GiB**) of plaintext.

| Encryptions with one key | Approx. collision probability |
|---|---|
| 1 | 0 |
| 2²⁰ (≈ 1 million) | 2⁻⁵⁷ |
| 2³² (≈ 4.3 billion, NIST limit) | 2⁻³³ |

**How the vault stays far below these limits:** since D3, every file gets a **fresh random 256-bit file key (DEK)**, and that key encrypts **exactly one** message. The key is never reused, so the number of encryptions per key is q = 1 and a nonce collision under the same key is impossible. The key-encryption keys used to wrap the DEK (D3) are also single-use: each one is derived from a fresh ephemeral ECDH exchange. If the module were ever changed to reuse a key, the limit to enforce would be 2³² encryptions per key, after which the key must be rotated.

## 6. Current Implementation (final system)

The single-key D2 module described above was replaced by the hybrid module in `vault/crypto_module.py` (see [`D3-Hybrid_Encryption.md`](D3-Hybrid_Encryption.md#update-for-the-final-system-container-v6)). The D2 feedback was addressed there:

| D2 feedback | Where it is addressed |
|---|---|
| Documentation did not match the code | This document now refers to `vault/crypto_module.py`, `SecureEncryptionModule` and the current tests. |
| Explicit container validation | `SecureEncryptionModule.parse_container()` validates every field (types, lengths, Base64, versions, algorithms, recipient entries) before any cryptographic operation. |
| Broad exception handler | Replaced by specific exceptions in `vault/errors.py` (`ContainerFormatError`, `SignatureError`, `AccessDeniedError`, `IntegrityError`, `RecipientError`), raised `from None` so internal details are not exposed. |
| Tests for modified AAD, nonces, ciphertext, malformed containers | `tests/test_signatures.py` and `tests/test_ecies_validation.py`. |
| Nonce uniqueness and per-key limits | Section 5 above. |
