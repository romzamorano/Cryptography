# Security Documentation — Secure Digital Document Vault

This document summarizes the security of the final system. The complete documentation, with diagrams, data formats and workflows, is in [FINAL_DOCUMENTATION.md](FINAL_DOCUMENTATION.md).

## Contents

1. [Threat model summary](#1-threat-model-summary)
2. [Cryptographic design decisions](#2-cryptographic-design-decisions)
3. [Canonicalization strategy](#3-canonicalization-strategy)
4. [Key management strategy](#4-key-management-strategy)
5. [Security audit findings](#5-security-audit-findings)
6. [Security requirements and evidence](#6-security-requirements-and-evidence)

---

## 1. Threat model summary

**System.** Users exchange files through an **untrusted** shared folder or channel. Each user's device (application, keystores, contacts, replay cache) is **trusted**.

**Assets.** File contents; file metadata (name, timestamp, recipients, signer); the per-file key (DEK); users' private keys; passwords; the binding between contacts and their public keys.

**Adversaries.**

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | Storage / channel attacker | Reads, copies, modifies, deletes, reorders and re-delivers packages |
| A2 | Impersonator | Owns valid keys, publishes fake public-key bundles, signs her own packages |
| A3 | Device / backup thief | Copies keystores or backups and guesses passwords offline |
| A4 | Malicious or former recipient | Knows the DEK of a file she received; tries to modify or re-send it as the original sender |
| A5 | Malformed-input attacker | Truncated packages, invalid Base64, huge numbers, invalid curve points |

**Assumptions.** Devices are free of malware and users keep their passwords secret; the OS random number generator is secure; public keys are bound to their owners by comparing fingerprints out of band (a fingerprint identifies a key but does not prove who owns it); the cryptographic primitives are not broken.

**Security goals.** R1 confidentiality · R2 integrity · R3 sender authenticity · R4 private-key confidentiality · R5 metadata tamper protection · R6 recipient authorization · R7 freshness (no replay) · R8 key lifecycle · R9 robust parsing · R10 safe file recovery.

**Out of scope.** Malware on the user's device, users revealing their password, availability (deletion of packages), a legitimate recipient forwarding the plaintext.

The 14 concrete attack scenarios (S1–S14), the attack surface and the traceability matrix are in [FINAL_DOCUMENTATION.md §3](FINAL_DOCUMENTATION.md#3-threat-model) and [D1](D1_Architecture_Threat_Model.md).

---

## 2. Cryptographic design decisions

| Decision | Choice | Justification |
|---|---|---|
| AEAD for files (D2) | **AES-256-GCM**, 128-bit tag | Confidentiality + integrity + authenticated associated data in one standard primitive (NIST SP 800-38D); hardware accelerated; never returns plaintext when the tag fails |
| Nonce strategy (D2) | Random 96-bit nonce (`os.urandom`) and a **fresh 256-bit key per file** | Each key encrypts exactly one message, so a (key, nonce) pair never repeats. Random nonces collide with probability ≈ q²/2⁹⁷ for q messages under one key; NIST limits them to 2³² per key; here q = 1 |
| Metadata protection (D2) | Header (`format`, `version`, `metadata`, `recipients`, `signer_id`) as **AES-GCM AAD** | File name, timestamp, algorithms and recipient list cannot be changed without failing authentication |
| Hybrid encryption (D3) | **ECIES-style**: ephemeral P-256 key → **ECDH** → **HKDF-SHA256** → AES-256-GCM key wrap of the DEK | Public-key cryptography only protects the 32-byte DEK; the file is encrypted once. The project forbids RSA; P-256 is the NIST curve seen in class |
| Recipient handling (D3) | Recipient `key_id` = `"p256:"` + SHA-256 of the uncompressed public point; capsules of exactly 125 bytes; point validated on the curve | Access depends on the key actually held, never on a self-declared name; invalid-curve and malformed capsules are rejected |
| Key-wrap context (D3) | HKDF `info` and wrap AAD = `"SDDV-v6/dek-wrap/" ‖ key_id ‖ "/" ‖ ephemeral point` | Domain separation; a capsule cannot be moved to another recipient or reused across versions |
| Signatures (D5) | **Ed25519** over `"SDDV-container-signature-v6\0" ‖ SHA-256(canonical JSON of every field except the signature)` (encrypt-then-sign) | Deterministic, non-malleable, no per-signature nonce; covers ciphertext, tag, nonce, metadata, recipients and signer identity |
| Verification (D5) | Signer must be a key **trusted for the expected sender**; signature verified **before** any key unwrapping or decryption | Prevents signature stripping / re-signing and keeps attacker-controlled data away from the private key and the decryption code |
| Key protection (D6) | Private keys encrypted with **AES-256-GCM**; whole keystore header as AAD | Stealing the file is not enough; metadata and KDF parameters cannot be tampered with |
| KDF (D6) | **PBKDF2-HMAC-SHA256**, 600,000 iterations (min), 10,000,000 (max), 16-byte salt | NIST SP 800-132 / RFC 8018, OWASP iteration count; bounds prevent downgrade and denial of service. Not memory-hard: Argon2id is the planned upgrade |
| Separation of keys | P-256 only for encryption, Ed25519 only for signing | No cross-protocol interactions; independent rotation |

---

## 3. Canonicalization strategy

Signer and verifier must compute **exactly the same bytes**, so every signed, authenticated or identifying value has a single canonical representation, and ambiguous input is rejected.

* **Canonical JSON** for signed data and AAD (packages and keystores): `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. A package can be reformatted on disk (key order, spaces) without breaking the signature, but changing any value breaks it.
* **Strict JSON parsing:** duplicated keys are rejected, the field set must be exact (no unsigned extra fields) and types are strict (`version` must be the integer `6`, not `"6"` or `true`).
* **Binary values:** Base64 decoded with `validate=True` and exact lengths (nonce 12, tag 16, signature 64, capsule 125 bytes).
* **Key fingerprints** over a single encoding: the 65-byte uncompressed X9.62 point for P-256, the raw 32 bytes for Ed25519, whatever format the key was loaded from.
* **Domain separation labels** in the signature input and in the key-wrap context.
* **Output file names** reduced to one safe spelling (`sanitize_filename`): last path component only, `\` treated as `/`, leading dots removed, control and reserved characters replaced, reserved Windows names prefixed.
* **Names and dates:** user/contact names limited to letters, digits, `-`, `_`, `.`; keystore dates in UTC ISO 8601 (`...Z`), package timestamps as integer Unix seconds.

Details and the table of every canonical form: [FINAL_DOCUMENTATION.md §4.3](FINAL_DOCUMENTATION.md#43-canonicalization-strategy).

---

## 4. Key management strategy

| Aspect | Strategy |
|---|---|
| Generation | P-256 and Ed25519 key pairs generated locally with the OS CSPRNG when a user is created |
| Storage | One JSON keystore per private key: PKCS#8 key encrypted with AES-256-GCM under a PBKDF2-derived key; header authenticated; atomic write; `0600` permissions; never overwritten by accident. Private keys are never written in plaintext and never leave the user's folder |
| Unlocking | Password read with `getpass` (no echo), never stored; the key is decrypted only for the operation and its reference dropped afterwards; the decrypted key must match the declared type and fingerprint |
| Password policy | ≥ 12 characters, not a common password, not only digits, ≥ 5 distinct characters, no simple sequences |
| Rotation | New key of the same type becomes `active`; the old one becomes `retired` and only opens / verifies **old** files; the public bundle is re-published |
| Compromise | Key marked `compromised` (never usable again, cannot be rotated) and replaced by a new key; contacts **revoke** it in their trust store, so packages signed with it are refused, old ones included |
| Expiration | Optional `expires_at`; expired keys behave like retired keys |
| Backup / recovery | Encrypted keystores copied without decrypting, verified byte by byte, never overwriting previous backups; restore checks password, integrity and the **expected key fingerprint** before writing anything |
| Distribution and trust | Public keys exchanged as bundles; fingerprints confirmed out of band; a different key under a known name raises `KeyChangedError` and is accepted only after explicit confirmation |
| Public repository | No private key is ever committed: runtime data lives in `vault_home/` (ignored by Git); see [`keys/`](../keys/README.md) |

---

## 5. Security audit findings

Sources: the instructor's reviews of D1–D6, the team's internal code review, adversarial tests, the attack lab, and testing on Windows and Linux. Every finding below is **fixed** and covered by an automated test.

| ID | Severity | Finding | Source | Fix | Verified by |
|---|---|---|---|---|---|
| F-01 | High | Recipient identifiers were free-text labels not bound to public keys: a key labelled "Bob" could belong to anybody | D3 review | `key_id` = fingerprint; entries located by the fingerprint of the private key; optional expected fingerprint checked before encrypting | `test_access_decided_by_key_not_by_label`, `test_expected_fingerprint_mismatch_rejected_on_encrypt` |
| F-02 | High | ECIES capsule not validated: variable-length DER, any key type accepted, invalid curve points reached ECDH | D3 review | Fixed 125-byte capsule, `0x04` prefix, point validated on P-256 | `TestCapsuleValidation` |
| F-03 | Medium | Key wrap used a fixed HKDF `info` and an empty AAD (no context binding) | D3 review | Context = version + recipient fingerprint + ephemeral key in HKDF `info` and AAD | `test_capsule_moved_to_other_recipient_rejected` |
| F-04 | High | AAD alone only protected against outsiders: a legitimate recipient (who knows the DEK) could rewrite the header and re-encrypt | Internal review (D3) | Ed25519 signature over the whole package, verified first against the trusted sender key | `test_8_forged_container_resigned_by_attacker_rejected` |
| F-05 | High | Signer identity was trusted as declared; no documented trust establishment | D5 review | Trust store with out-of-band fingerprint confirmation and key-change detection | `test_2_unknown_sender_rejected`, `test_3_key_substitution_attack_detected` |
| F-06 | Medium | Genuine old packages could be replayed | D5 review | Signed timestamp with a 30-day window + per-user cache of received packages | `test_8_replayed_package_rejected`, `test_10_stale_package_rejected` |
| F-07 | Medium | No revocation of compromised keys | D5 / D6 review | `mark_compromised` (own keys) and trust-store revocation (contacts' keys) | `test_5_revoked_sender_key_rejects_old_and_new_files`, `test_compromised_key_refused` |
| F-08 | Medium | Broad `except Exception` handlers masked bugs and produced inconsistent errors | D2 review | Exception hierarchy (`errors.py`), errors raised `from None` | `test_all_failures_are_vault_errors_without_internal_cause` |
| F-09 | Medium | Malformed containers were rejected only by accident | D2 review | Strict `parse_container()` before any cryptographic operation | `TestMalformedContainers` |
| F-10 | High | Keystores written with `open(path, 'w')`: default permissions and silent overwriting | D6 review | Atomic write, `0600`, `overwrite=False` by default (create-only hard link) | `TestNoAccidentalOverwrite`, `test_keystore_file_permissions` |
| F-11 | High | Keystore metadata and KDF parameters not authenticated | D6 review | Whole header as AES-GCM AAD | `test_3_modified_keystore_failure` |
| F-12 | Medium | Unbounded iteration count: an edited keystore could hang the application (DoS) | Internal review | Iterations limited to 600,000–10,000,000, checked before deriving | `test_huge_iteration_count_rejected_before_deriving` |
| F-13 | Medium | Weak passwords accepted | D6 review | Password policy | `TestPasswordPolicy` |
| F-14 | Medium | Restore did not verify the identity of the restored key | D6 review | `expected_fingerprint` checked before writing | `test_restore_verifies_expected_fingerprint` |
| F-15 | Medium | Path traversal: the file name stored in a package was trusted when saving | Internal review | `sanitize_filename()`, inbox only, never overwriting | `test_output_filename_is_sanitized` |
| F-16 | Low | Output could overwrite existing files or be written before every check passed | Internal review | Exclusive creation, unique names, write only after all six checks | `test_failed_step_is_reported_and_nothing_written` |
| F-17 | Low | On Windows, opening a directory as a keystore raised `PermissionError` and was misreported | Team testing on Windows | Directory check before opening | `test_file_errors_are_controlled` |
| F-18 | Low | Missing/unreadable keystore files raised raw OS errors | D6 review | `KeystoreNotFoundError` / `KeystoreError` | `test_file_errors_are_controlled`, `test_unreadable_file_is_controlled` |
| F-19 | Info | Random-nonce uniqueness was not justified | D2 review | Documented bound; one DEK per file | `test_each_file_uses_a_fresh_file_key_and_nonce` |
| F-20 | Info | Documentation did not match the implementation | D2 review | Documents updated; final documentation generated from the code | — |

### Accepted residual risks

| Risk | Reason it is accepted | Possible mitigation |
|---|---|---|
| Package metadata (file name, recipients, dates) visible | Needed to route and verify packages; it is authenticated | Encrypt the file name; pad ciphertext lengths |
| PBKDF2 is not memory-hard | Standard, audited and available everywhere; compensated by iterations and policy | Migrate to Argon2id |
| Keys cannot be reliably wiped from Python memory | Language limitation | Native implementation with memory zeroing |
| `chmod 0600` has limited effect on Windows | Windows relies on profile ACLs | Explicit ACLs |
| Deletion of packages (availability) | Out of scope of the threat model | Redundant storage, delivery receipts |

---

## 6. Security requirements and evidence

| Requirement | Implementation | Tests |
|---|---|---|
| Correct AEAD usage | AES-256-GCM via `cryptography`'s `AESGCM`; tag verified before any plaintext is returned | `test_2_modified_ciphertext_rejected`, `test_tampered_ciphertext_behind_valid_signature_releases_no_plaintext` |
| Proper nonce handling | 96-bit `os.urandom` nonce per encryption; fresh DEK per file; exact length checks | `test_each_file_uses_a_fresh_file_key_and_nonce`, `test_unique_salt_and_nonce` |
| AAD protection | Package header and keystore header as AAD | `test_3_modified_metadata_rejected`, `test_3_modified_keystore_failure` |
| Signature verification before decryption | `decrypt_file` calls `verify_container` first | `test_11_signature_verified_before_decryption` |
| Secure key storage | Encrypted keystores, authenticated header, `0600`, no overwrite | `test_5_stolen_keystore_alone_cannot_decrypt`, `TestNoAccidentalOverwrite` |
| Fail-closed behavior | Any failed check stops the flow; nothing written or recorded; corrupted state raises errors | `test_failed_step_is_reported_and_nothing_written`, `test_corrupted_cache_does_not_disable_protection` |
| Input validation | Strict parsers for packages, capsules, keystores, bundles and names | `TestMalformedContainers`, `TestMalformedKeystores`, `test_malformed_bundles_rejected` |
