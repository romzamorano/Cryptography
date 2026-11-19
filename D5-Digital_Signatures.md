# Cryptography — Secure Digital Document Vault (Deliverable 5: Digital Signatures)

This is the repository for the development of the Cryptography project.

The team consists of:
* Carballo Ramírez Hanny
* Monter González Luis Enrique
* Siliano Haller Rodrigo
* Romero Zamorano Rosa Jennifer

---

## Overview

Up to D3 the vault provided **confidentiality** (AES-256-GCM) and **access control** (per-recipient ECIES key wrapping). It did **not** tell a recipient *who* created a file: anyone holding a recipient's public key could build a brand-new, perfectly valid container and claim to be the owner.

In **Deliverable 5 (D5)** every container is **digitally signed by its creator** with **Ed25519**. A recipient can now:

* verify **who created the file** (origin authentication),
* detect **any modification** of the ciphertext, the tag, the nonce, the metadata, the recipient list or the signer identity (integrity),
* **reject** forged, re-signed, unsigned or tampered containers **before** anything is decrypted.

```
Sender:    Encrypt  →  Add metadata  →  Hash (SHA-256)  →  Sign (Ed25519)  →  Store
Recipient: Read  →  Extract metadata + ciphertext  →  Verify signature  →  valid? decrypt : reject
```

---

## Signature Design

### 1. Algorithm chosen: Ed25519

| Property | Value |
|---|---|
| Algorithm | **Ed25519** (EdDSA over Curve25519, RFC 8032) |
| Security level | ~128 bits |
| Private / public key | 32 bytes / 32 bytes |
| Signature size | 64 bytes |
| Library | `cryptography` (`Ed25519PrivateKey`, `Ed25519PublicKey`) |

Why Ed25519 instead of ECDSA:

* **Deterministic signatures.** ECDSA needs a fresh random nonce `k` per signature; a repeated or biased `k` leaks the private key (the Sony PS3 failure). Ed25519 derives its nonce deterministically from the key and the message, so a bad RNG at signing time cannot leak the key.
* **No malleability / fewer edge cases.** Encodings are fixed-length, and verification rejects non-canonical signatures.
* **Fast and small**, with a constant-time reference implementation.

**Consistent key sizes.** All keys in the system are 256-bit (AES-256, P-256, Ed25519, HKDF-SHA256), providing a consistent security level of at least 128 bits, so no component is weaker than the others.

| Component | Algorithm | Key size | Security level |
|---|---|---|---|
| File key | AES-256-GCM | 256 bits | 256 bits |
| Users' encryption keys | ECIES P-256 | 256 bits | ~128 bits |
| Key-wrapping key | HKDF-SHA256 | 256 bits | 256 bits |
| Signing keys | Ed25519 | 256 bits | ~128 bits |
| Hash | SHA-256 | 256-bit output | ~128 bits (collisions) |

**Key separation.** Each user now has **two** key pairs: a P-256 pair for **encryption** (ECIES, from D3) and an Ed25519 pair for **signing** (D5). Using one key for two different purposes is avoided because an attack on one usage could compromise the other.

### 2. What data is signed

The signature covers **every field of the container except the signature itself**:

| Field | Signed | Also in AES-GCM AAD | Why |
|---|:---:|:---:|---|
| `format`, `version` | ✅ | ✅ | Prevents downgrade / format confusion |
| `metadata` (filename, algorithm, signature_algorithm, timestamp) | ✅ | ✅ | Prevents metadata and context manipulation |
| `recipients` (id + wrapped file key) | ✅ | ✅ | Prevents adding, removing or swapping recipients |
| `signer_id` | ✅ | ✅ | Binds the signer identity to the content |
| `nonce` | ✅ | — | Part of the encrypted output |
| `ciphertext` | ✅ | — | The encrypted content (output of D2) |
| `tag` | ✅ | — | GCM authentication tag |
| `signature` | — | — | It is the result of signing |

Exact construction (`SecureEncryptionModule._signed_digest`):

```
signed_fields = container without "signature"
canonical     = JSON(signed_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
digest        = SHA-256(canonical)
message       = b"SDDV-D5-container-signature-v1\x00" || digest
signature     = Ed25519.sign(signer_private_key, message)
```

* **Canonical serialization** (sorted keys, no whitespace) guarantees that sender and recipient hash exactly the same bytes, regardless of how the JSON file was formatted on disk.
* **Domain separation** (`SDDV-D5-container-signature-v1`) ensures a signature produced by the vault cannot be reused as a valid signature in another protocol, and vice-versa.

### 3. Why hashing is required before signing

1. **Fixed-size input.** Signature algorithms operate on a fixed-size value; hashing turns a file of any size (kilobytes or gigabytes) into a 32-byte digest, so signing cost does not depend on file size.
2. **Integrity binding.** Thanks to the collision and second-preimage resistance of SHA-256, it is computationally infeasible to find a different container with the same digest; signing the digest is therefore equivalent to signing the whole container — **changing a single bit changes the digest and invalidates the signature**.
3. **Security of the scheme.** The security proofs of signature schemes assume a hashed (random-looking) input; signing raw structured data directly would allow algebraic / existential forgeries in schemes such as textbook RSA.
4. **Efficiency in multi-step pipelines.** The digest can be computed while streaming the file and signed once at the end.

> Note: Ed25519 also hashes internally with SHA-512 as part of its design (RFC 8032). Our explicit SHA-256 step defines **exactly** which bytes are covered and fixes the message length, as required by the deliverable.

### 4. Signer identification

```
signer_id = "ed25519:" + hex( SHA-256( raw 32-byte Ed25519 public key ) )
```

This is a **key fingerprint** (same idea as SSH / OpenPGP fingerprints). The recipient is configured with the **trusted public key** of the expected sender and the vault checks:

1. `signer_id` == fingerprint of the trusted public key → otherwise **reject** (wrong / unknown signer);
2. the signature verifies with that public key → otherwise **reject**.

The `signer_id` is only an identifier: it is never trusted by itself, because an attacker can write any value there. Trust comes from the public key the recipient already has (in a real deployment, distributed through a PKI / X.509 certificate, as in Practical Session 6).

### 5. Signature encoding

* The signature is the raw **64-byte Ed25519 signature defined in RFC 8032** (`R || S`).
* It is stored inside the JSON container encoded in **standard Base64 (RFC 4648, §4)**, the same encoding already used for binary values in D3.
* Binary fields (`nonce`, `ciphertext`, `tag`, `signature`) are decoded in **strict mode** (`validate=True`) and their lengths are checked (nonce = 12, tag = 16, signature = 64 bytes).
* Signing keys are exported as **PEM / PKCS#8** (private) and **PEM / SubjectPublicKeyInfo** (public), as shown in `demo.py`.

---

## Container Format (D5)

The container is now a JSON document (UTF-8) with exactly these fields:

```json
{
  "format": "SDDV",
  "version": 5,
  "metadata": {
    "algorithm": "AES-GCM-256 + ECIES(P-256)",
    "filename": "secret.txt",
    "signature_algorithm": "Ed25519",
    "timestamp": 1793925600
  },
  "recipients": [
    { "id": "Alice", "encrypted_key": "<base64 ECIES payload>" },
    { "id": "Bob",   "encrypted_key": "<base64 ECIES payload>" }
  ],
  "nonce": "<base64, 12 bytes>",
  "ciphertext": "<base64>",
  "tag": "<base64, 16 bytes>",
  "signer_id": "ed25519:6c0239bf5204db23...",
  "signature": "<base64, 64 bytes>"
}
```

Parsing is **strict**: a container is rejected if a field is missing, if the signature is missing or empty, if there are **extra (unsigned) fields**, if a JSON key is duplicated, or if `format` / `version` are not supported.

---

## Verification Workflow

`decrypt_file(container, my_private_key, my_key_id, sender_public_key)`:

1. **Read container** — parse JSON; reject if invalid.
2. **Extract metadata + ciphertext** — check all required fields; reject if the signature was removed or extra fields were added.
3. **Verify signature** — check `signer_id` against the trusted key, recompute the digest and verify Ed25519.
4. **If valid →** look up `my_key_id` in `recipients`, unwrap the file key (ECIES) and decrypt (AES-GCM, with the header as AAD).
5. **If invalid →** raise `ValueError("Firma Rechazada: ...")`. No ECIES or AES operation is ever performed on an unverified container (checked by `test_11_signature_verified_before_decryption`).

---

## Security Decisions

### Why sign the ciphertext and not the plaintext? (Encrypt-then-Sign)

* **Verify before decrypting.** Signing the ciphertext lets the recipient reject a tampered or forged container **without touching the private key or running the decryption code**, which reduces the attack surface (padding / decryption oracles, malformed-input bugs, DoS).
* **Signature does not leak the content.** A signature over the plaintext is a deterministic function of the plaintext (Ed25519 is deterministic): anyone could test guesses of the content (“is this file X?”) against the public signature. A signature over the ciphertext reveals nothing about the plaintext.
* **It covers what is actually stored and transmitted** — ciphertext, tag, nonce **and** the recipient list. A plaintext signature would not stop an attacker from changing the recipient list or the metadata.
* **Third parties can check integrity/origin** (e.g. the storage server) without being able to read the file.
* The usual weakness of “sign the ciphertext” — someone stripping the signature and re-signing as themselves — is addressed because the recipient checks the signer against a **trusted public key** (`signer_id` + verification), and the signer identity is also included in the AAD, so a re-signed container is rejected (`test_8_forged_container_resigned_by_attacker_rejected`).

### What happens if the signature is not verified first?

* The system would process **attacker-controlled input** with the recipient's private key (ECIES) and with the AES-GCM decryption code. This opens the door to oracle attacks, parsing bugs and resource exhaustion with forged files.
* A forged container built by anyone who knows the recipients' **public** keys would decrypt correctly with AES-GCM (the attacker chose the file key), so the recipient would **accept content from an impostor**. AES-GCM only proves that whoever knows the file key built the file — not who that person is.
* Any plaintext released before the signature check (streaming, previews, temporary files) could not be “taken back” once the check fails.

For this reason `decrypt_file` calls `verify_container` first and only continues if it returns successfully.

### What happens if metadata is excluded from the signature?

* An attacker could **change the filename or type** (e.g. `report.pdf` → `report.exe`), the **timestamp** (replay old versions as new), or the **algorithm** fields (downgrade attempts) and the signature would still be valid.
* An attacker could **modify the recipient list** — remove a legitimate recipient (denial of access) or swap recipient IDs — without invalidating the signature.
* An attacker could change `signer_id` to **misattribute** the file.
* These are **context-manipulation attacks**: the content is authentic, but it is presented in a false context. Signing *all* security-relevant metadata (the same data used as AAD) prevents them.

---

## Required Tests

`tests/test_signatures.py`:

| Test | Scenario | Expected |
|---|---|---|
| `test_1_valid_signature_file_accepted` | Valid signature | ✅ Accepted and decrypted |
| `test_2_modified_ciphertext_rejected` | One bit of the ciphertext flipped | ❌ Rejected |
| `test_3_modified_metadata_rejected` | Filename / timestamp changed | ❌ Rejected |
| `test_4_wrong_public_key_rejected` | Verified with Eve's public key | ❌ Rejected |
| `test_5_signature_removed_rejected` | `signature` deleted / empty | ❌ Rejected |
| `test_6_modified_tag_or_nonce_rejected` | Tag or nonce modified | ❌ Rejected |
| `test_7_modified_recipients_rejected` | Recipient removed | ❌ Rejected |
| `test_8_forged_container_resigned_by_attacker_rejected` | Eve modifies and re-signs with her key | ❌ Rejected |
| `test_9_modified_signer_id_rejected` | `signer_id` replaced | ❌ Rejected |
| `test_10_extra_unsigned_field_rejected` | Extra field added | ❌ Rejected |
| `test_11_signature_verified_before_decryption` | Tampered file | ❌ Rejected **before** ECIES runs |

The D3 tests (`tests/test_crypto.py`) were updated to the signed container and still pass.

```bash
python -m unittest discover -s tests -v
```

---

## Trust Establishment, Revocation and Replay Protection (final system)

These additions answer the D5 recommendations: document how signing keys become trusted, and address key revocation and replay protection. Implemented in `vault/trust_store.py` and `vault/replay_guard.py`.

### 1. How a signing key becomes trusted

A fingerprint identifies a key but does not prove who owns it. Trust is established once, out of band (like Signal safety numbers or SSH host keys):

1. Alice exports her **public key bundle** (`SDDV-PUBLIC-KEYS`): her name, her P-256 encryption public key, her Ed25519 signing public key and both fingerprints.
2. Bob imports the bundle. The application validates it (the fingerprints must match the keys, key types must be P-256 and Ed25519) and **shows both fingerprints**.
3. Bob confirms the fingerprints with Alice through an independent channel (in person, by phone). Optionally he types them: if they do not match the keys, the import is refused.
4. The keys are stored in Bob's **trust store** (`SDDV-TRUSTSTORE`, a local file with `0600` permissions) under the name "Alice".

From then on, when Bob opens a file "from Alice", the application reads the `signer_id` declared in the package, looks it up **only among the keys trusted for Alice**, and verifies the signature with that key. A key that is not trusted for Alice is rejected, even if its signature is mathematically valid.

| Situation | Behavior | Error |
|---|---|---|
| Package signed by a key not trusted for the expected sender | Rejected | `SignatureError` |
| Bundle under a known name with **different** keys (possible key substitution) | Refused unless the user confirms the change | `KeyChangedError` |
| Bundle whose keys do not match the fingerprints the user typed | Refused | `TrustStoreError` |

### 2. Rotation and revocation of contact keys

Each trusted key has a status:

| Status | Meaning | Verify old files | Encrypt new files for it |
|---|---|---|---|
| `active` | Current key of the contact | ✅ | ✅ |
| `retired` | Replaced by a rotation the user accepted | ✅ (files signed before the rotation) | ❌ |
| `revoked` | Reported compromised | ❌ (old **and** new files) | ❌ |

* **Rotation:** Alice rotates her keys (D6 `rotate_key`) and re-publishes her bundle. Bob imports it; the application warns that the key changed and, after Bob confirms the new fingerprint, the old key becomes `retired`.
* **Revocation:** Alice reports that her laptop was stolen. Bob marks her key as `revoked`. Every package signed with that key is refused from then on (an attacker holding the stolen key could sign new packages with old timestamps), and a revoked key can never be trusted again, not even under another name.
* On her own side, Alice marks her key as `compromised` in her keystore (D6), so the application refuses to use it.

### 3. Replay protection

A replayed package has a **valid signature**: the attacker re-delivers an old genuine package (for example, an outdated set of instructions) so it is treated as new. Two checks are applied **after** the signature is verified and **before** decrypting:

1. **Freshness window:** the signed `timestamp` must be at most **30 days** old and at most **5 minutes** in the future. The timestamp is signed, so the attacker cannot refresh it.
2. **Seen-package cache:** each user keeps a cache of the identifiers of the packages already accepted (`SHA-256` of the signed data). The same package is refused the second time.

The identifier is only recorded **after a successful decryption**, so a tampered copy cannot block the genuine package. Entries older than the window are pruned, because such packages are rejected by the freshness check anyway. A corrupted cache raises an error instead of silently disabling the protection.

| Test file | What it verifies |
|---|---|
| `tests/test_trust_store.py` | Bundles, expected fingerprints, key-change detection, rotation (retired keys), revocation |
| `tests/test_replay_guard.py` | Freshness window, seen cache, persistence, pruning, corrupted cache |
| `tests/integration/test_trust_and_replay_flow.py` | The full flow: trusted exchange, unknown sender, key substitution, revoked sender, rotation, replay, stale package |
