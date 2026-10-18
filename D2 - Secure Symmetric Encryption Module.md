# Deliverable 2 (D2): Core Cryptographic Module Implementation

**Branch:** `feature/d2-crypto-module`

## Overview of What Was Implemented

For **Deliverable 2**, we designed and implemented the core symmetric cryptographic engine of the **Secure Digital Document Vault**. Instead of relying on legacy unauthenticated modes (such as AES-CBC, which are vulnerable to padding oracle and ciphertext manipulation attacks), this module implements **Authenticated Encryption with Associated Data (AEAD)** using **AES-256-GCM** (Galois/Counter Mode).

The implementation is divided into two main components:
1. **`encryption.py` (`SecureVaultCrypto`):** The cryptographic engine responsible for key generation, nonce management, authenticated file/data encryption, metadata binding, and fail-safe decryption.
2. **`test_encryption.py`:** An adversarial unit test suite that validates both functional correctness and cryptographic failure modes under tampering attacks.

---

## 1. Core Cryptographic Engine (`encryption.py`)

The `SecureVaultCrypto` class encapsulates all low-level cryptographic primitives using Python's `cryptography` library (`AESGCM`), preventing misuse of keys and nonces across the application.

### A. 256-Bit Key Generation and Validation
* **Implementation:** The module enforces the use of **256-bit (32-byte)** symmetric keys generated via a Cryptographically Secure Pseudo-Random Number Generator (**CSPRNG**).
* **How it works:** Upon instantiation, `SecureVaultCrypto` validates the key length before initializing the underlying `AESGCM` cipher context. This provides $2^{256}$ keyspace security, protecting stored documents against brute-force attacks and meeting NIST SP 800-38D standards.

### B. Dynamic Nonce Management (96-Bit CSPRNG)
* **Implementation:** Every single encryption call dynamically generates a fresh **12-byte (96-bit) random nonce** using `os.urandom(12)`.
* **How it works:** In AES-GCM, reusing a `(Key, Nonce)` pair catastrophically compromises both confidentiality (via keystream XOR recovery) and integrity (by exposing the internal GHASH authentication key). By generating a cryptographically random 96-bit nonce inside the encryption method itself—rather than requiring the caller to pass one—the implementation guarantees **semantic security**: encrypting the exact same document twice with the same key produces two completely different ciphertexts.

### C. Authenticated Encryption & Binary Packaging
* **Implementation:** The encryption logic takes the plaintext payload (or source file) and optional **Associated Authenticated Data (AAD)**, encrypts the data using AES-256 in Counter (CTR) mode, and computes a **128-bit (16-byte) Galois Message Authentication Code (GMAC/Tag)**.
* **How the output is structured:** To make encrypted files self-contained for decryption, the implementation prepends the 12-byte nonce directly to the output stream followed by the ciphertext and the 16-byte authentication tag:

```text
+-----------------------+-----------------------------------+----------------------------+
|   Nonce (12 bytes)    |     Ciphertext (N bytes)          |   GCM Auth Tag (16 bytes)  |
|   96-bit CSPRNG IV    |   AES-256-CTR Encrypted Payload   |   128-bit GHASH Integrity  |
+-----------------------+-----------------------------------+----------------------------+
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

## 3. Adversarial Test Suite Implementation (`test_encryption.py`)

To prove that the cryptographic implementation enforces its security guarantees, we implemented a suite of automated unit tests covering both normal execution and active tampering scenarios:

1. **Lossless Round-Trip Verification:** Encrypts sample documents and verifies that decrypting with the matching key and AAD restores the exact bit-for-bit original plaintext.
2. **Semantic Security (Nonce Uniqueness):** Encrypts the exact same document twice under the same 256-bit key and verifies that both the resulting 12-byte nonces and ciphertexts are completely distinct.
3. **Ciphertext Tampering Detection (Bit-Flip Attack):** Simulates an attacker flipping a single bit inside the encrypted payload of a vault file and asserts that the decryption routine rejects the file with an authentication error rather than returning corrupted plaintext.
4. **Metadata / AAD Tampering Detection:** Simulates an attacker attempting to spoof file metadata (providing modified AAD during decryption while keeping the key and ciphertext intact) and verifies that the GCM tag verification fails immediately.
5. **Unauthorized Key Rejection:** Attempts to decrypt a valid vault container using a newly generated 256-bit key and asserts that authentication fails safely.
