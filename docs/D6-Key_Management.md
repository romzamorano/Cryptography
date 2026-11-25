# Deliverable 6 — Secure Key Management

**Security goal:** private keys must remain confidential and usable only by authorized users, **even if storage is compromised**.

D2–D5 already encrypt (AES-256-GCM), share (ECIES P-256) and authenticate (Ed25519) files. All of that collapses if a private key is exposed, so D6 adds a password-protected **keystore** (`vault/keystore.py`) that protects the two private keys each user owns:

| Key | Algorithm | Used for | Keystore file |
|---|---|---|---|
| Encryption key | ECDH P-256 | Unwrap the file key of shared files (ECIES, D3) | `<user>_p256.json` |
| Signing key | Ed25519 | Sign containers (D5) | `<user>_ed25519.json` |

Public keys are not secret: they are exported as PEM files and also stored (with their fingerprint) inside the keystore metadata.

---

## 1. Private key protection

Private keys are **never written to disk in plaintext**. The protection pipeline is:

```
password ──► PBKDF2-HMAC-SHA256 (random 16-byte salt, 600,000 iterations) ──► 256-bit KEK
private key (PKCS#8) ──► AES-256-GCM(KEK, random 12-byte nonce, AAD = keystore header) ──► ciphertext + tag
```

* The **KEK** (key-encryption key) only exists in memory while the keystore is being opened.
* The **AAD** is the canonical JSON of `format`, `version`, `metadata` and `kdf_parameters`. Any change to the key ID, key type, status, expiration date, salt or iteration count makes the GCM tag check fail.
* Files are written atomically and with owner-only permissions (`0600` on Linux/macOS).

## 2. Password-based access to keys

| Requirement | How the system meets it |
|---|---|
| Prompt for password when accessing private keys | `prompt_password()` / `unlocked_key()` use `getpass`: the password is not echoed and does not end up in shell history (D1, *Password entry*). |
| Derive the encryption key using a KDF | `_derive_key()` uses the salt and iteration count **stored in the keystore**, so old keystores still open if the default changes. |
| Decrypt the private key only when needed | `with keystore.unlocked_key(path) as priv:` decrypts the key for one operation and drops the reference when the block ends. |
| Do NOT store the password | The password is never written to disk, logs or the keystore (checked by `test_password_is_prompted_and_not_stored`). |
| Do NOT cache decrypted keys indefinitely | There is no key cache: every operation asks for the password again. |

Example (decrypting a file shared with Alice):

```python
from vault.keystore import SecureKeyStore
from vault.crypto_module import SecureEncryptionModule

keystore = SecureKeyStore()
vault = SecureEncryptionModule()

with keystore.unlocked_key("keystore/Alice_p256.json") as alice_priv:   # asks for the password
    plaintext = vault.decrypt_file(container, alice_priv, "Alice", alice_sign_pub)
# here the decrypted private key is no longer referenced
```

## 3. KDF selection and parameters

| Parameter | Value | Reason |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA256 | Standard (NIST SP 800-132, RFC 8018), available in every version of `cryptography`, already used by the team. |
| Iterations | **600,000** (default **and minimum**) | OWASP Password Storage Cheat Sheet value for PBKDF2-HMAC-SHA256. Around 0.1–0.5 s per unlock: unnoticeable for a user, very expensive for an attacker testing millions of passwords. |
| Salt | 16 random bytes per keystore (`os.urandom`) | Two users with the same password get different KEKs, and precomputed (rainbow) tables are useless. |
| Output | 32 bytes | AES-256 key. |
| Password policy | At least 12 characters; not in a list of common passwords; not only digits; at least 5 different characters; no simple sequences (`abcd…`, `1234…`) | Applied when a keystore is created and when the password is changed. Reduces the risk of trivial dictionary passwords (see §11). |
| Maximum iterations | 10,000,000 | A keystore asking for more is rejected **before** deriving, so an edited file cannot hang the application (denial of service). |

**Downgrade protection:** a keystore that asks for fewer iterations than `min_iterations` is rejected *before* deriving anything, so an attacker cannot edit the file to make brute force cheaper.

**Why PBKDF2 and not Argon2id or scrypt?**

| KDF | Memory-hard | Status in this project |
|---|---|---|
| **PBKDF2-HMAC-SHA256** | No (CPU-hard only) | **Chosen.** Approved by NIST (SP 800-132) and specified in RFC 8018; it is the KDF covered in the course and the most widely audited and interoperable option. Its cost is controlled by one parameter (iterations), which keeps the format and the downgrade/DoS checks simple. |
| scrypt | Yes | Also available in `cryptography`. Stronger against GPUs/ASICs, but it is not NIST-approved and needs three parameters (N, r, p) to validate. |
| Argon2id | Yes | Winner of the Password Hashing Competition and the first choice of OWASP; only available in recent versions of `cryptography` (≥ 44), and our `requirements.txt` supports ≥ 42. |

The trade-off is explicit: PBKDF2 is **not memory-hard**, so an attacker with GPUs can test passwords faster than against Argon2id or scrypt (see the offline guessing threat in §11). We compensate with the OWASP iteration count and the password policy, and the format is ready to migrate: `kdf_parameters.algorithm` and `version` identify the KDF, so a future version can accept Argon2id keystores and `change_password()` re-encrypts the key with the new KDF.

## 4. Key storage format

Each private key is stored in its own JSON file:

```text
demo_files/
├── keystore/
│   ├── Alice_p256.json        # encryption key (P-256), encrypted
│   ├── Alice_ed25519.json     # signing key (Ed25519), encrypted
│   └── Bob_p256.json
├── backup_usb/                # encrypted backups
│   └── Alice_20261116T045348Z.keystore.json
└── Alice_public.pem           # public keys (not secret)
```

```json
{
    "format": "SDDV-KEYSTORE",
    "version": 1,
    "metadata": {
        "key_id": "Alice",
        "key_type": "P-256",
        "purpose": "encryption",
        "encryption": "AES-256-GCM",
        "public_key": "-----BEGIN PUBLIC KEY-----\n...",
        "public_key_fingerprint": "p256:f70ebd014dbfe8d8720df57ecc718bbcfb96584876476be01e56eed7fc32bb6d",
        "created_at": "2026-11-16T04:53:47Z",
        "expires_at": null,
        "status": "active"
    },
    "kdf_parameters": {
        "algorithm": "PBKDF2HMAC-SHA256",
        "iterations": 600000,
        "key_length": 32,
        "salt": "<base64, 16 bytes>"
    },
    "nonce": "<base64, 12 bytes>",
    "encrypted_private_key": "<base64>",
    "tag": "<base64, 16 bytes>"
}
```

| Field | Meaning | Protected by |
|---|---|---|
| `format`, `version` | Identifies the file type and version of the format | AAD |
| `metadata.key_id` | Identity used in the recipient list of D3 containers | AAD |
| `metadata.key_type` / `purpose` | `P-256` → `encryption`, `Ed25519` → `signing` | AAD |
| `metadata.public_key`, `public_key_fingerprint` | Public key and its SHA-256 fingerprint (`p256:` / `ed25519:` — the same value as `signer_id` in D5) | AAD + identity check |
| `metadata.created_at`, `expires_at`, `status` | Lifecycle (`active`, `retired`, `compromised`) | AAD |
| `kdf_parameters` | Salt and KDF parameters needed to derive the KEK | AAD + minimum iterations |
| `nonce`, `encrypted_private_key`, `tag` | AES-256-GCM output (PKCS#8 private key encrypted) | GCM tag |

Parsing is strict: unknown or missing fields, duplicated JSON keys, invalid Base64, wrong lengths, unknown KDF or format are rejected.

## 5. Key lifecycle

| Stage | What the system does | Function |
|---|---|---|
| **Generation** | Keys are generated locally with the OS CSPRNG (`ec.generate_private_key(SECP256R1)`, `Ed25519PrivateKey.generate()`) and encrypted **immediately** into the keystore. Only the public key is exported. | `encrypt_and_save_key()` |
| **Usage** | The password is requested, the key is decrypted for one operation (decrypt a file / sign a container) and then discarded. The system checks that the decrypted key matches the type and fingerprint in the metadata. Only `active` and non-expired keys are used for new operations. | `unlocked_key()`, `load_and_decrypt_key()` |
| **Password change** | The same key is re-encrypted with a new password, a new salt and a new nonce. | `change_password()` |
| **Rotation** | A new key of the same type is generated and stored as `active`; the old keystore becomes `retired`. Retired keys can still open **old** files (`allow_inactive=True`) but are refused by default. The new public key must be sent to the other users, and new files are shared with the new key ID. | `rotate_key()` |
| **Compromise response** | 1) Mark the key as `compromised` → the system refuses it forever (even with `allow_inactive=True`). 2) Generate a new key pair and distribute the new public key/fingerprint out-of-band. 3) Ask senders to re-share important files with the new key (new file key, new ECIES wrap). 4) For a signing key: tell recipients to stop trusting the old `signer_id`. | `mark_compromised()` |
| **Expiration** (optional) | `expires_at` can be set when the key is created. After that date the key is refused for normal use and must be rotated; it can still open old files with `allow_inactive=True`. | `encrypt_and_save_key(..., expires_at=...)` |

> **Limitation:** revocation is local (there is no revocation server, which D1 left out of scope). Other users learn about a rotation or compromise through the same out-of-band channel used to exchange public keys. If the password is unknown (e.g. the laptop was stolen) the user cannot edit the stolen copy; they simply stop using that key, generate a new one and notify their contacts.

## 6. Key backup and recovery

* **Backup:** `backup_keystore(path, backup_dir)` copies the **encrypted** keystore to another place (USB drive, external disk, cloud folder). It does not need the password and never decrypts the key, so the backup is as safe as the original: someone who steals the backup still needs the password.
* **Restore:** `restore_keystore(backup, password, dest)` first **verifies** the backup (correct password, intact GCM tag, consistent key identity) and only then writes it, with `0600` permissions. A wrong password or a modified backup restores nothing, and an existing keystore is not overwritten unless `overwrite=True`.
* **Recommendations:** keep at least one offline copy, back up again after every rotation or password change, and remember that **the password is not recoverable**: if it is forgotten, the backup is useless (this is intentional — there is no back door).

## 7. Access control via keys

* **Only users with the correct private key can decrypt.** The file key of a container (D3) is wrapped with ECIES for each recipient's public key, so opening a file requires the matching private key, which only exists encrypted inside its owner's keystore. Without the keystore **and** the password there is no private key, and without the private key there is no file key.
* **Sharing still depends on encrypted file keys (D3).** D6 does not change the container: it only changes where the private key comes from (`unlocked_key()` instead of a plaintext PEM).
* **Key identity is consistent.** Every keystore stores `key_id`, `key_type`, `purpose` and the public key fingerprint, and all of them are authenticated. After decrypting, the system checks that the private key really matches that type and fingerprint. The Ed25519 fingerprint is exactly the `signer_id` used in D5.
* **No ambiguity in key usage.** P-256 keys are only for encryption (ECIES) and Ed25519 keys are only for signing; a key cannot be stored under the wrong type (`test_key_type_mismatch_rejected`) and each user has one active key per purpose.

## 8. Threat model alignment (revisiting D1)

D1 lists *private keys* and *passwords* as assets and requires *"Confidentiality of private keys: private keys must never leave the user local keystore in plaintext"*. D1 also assumed that *"the local client environments ... are secure and free of malware"*. D6 keeps that assumption but now also considers what happens when part of it fails.

**What if an attacker steals the keystore?**
They get the salt, KDF parameters, metadata and the encrypted key, but **not** the private key. To use it they must guess the password offline, and each guess costs 600,000 HMAC-SHA256 iterations. With a strong password this is not feasible. Modifying the keystore (e.g. lowering the iterations, swapping the key ID or pasting another user's ciphertext) is detected. The public metadata (key ID, public key, dates) is visible, which is acceptable because it is not secret.

**What if a password is weak?**
The KDF only slows the attack down; it cannot add entropy. A password from a dictionary list can be found in hours or days with GPUs, and then the attacker gets the private key and can decrypt every file shared with that key and sign as the user. Mitigations: minimum length of 12 characters, long passphrases, high iteration count, random salts (no precomputation), and rotating the key if a weak password was used.

**What if a device is compromised?**
If malware runs on the user's computer (keylogger, memory dump, root access), it can capture the password while it is typed or read the private key from RAM while it is in use. D6 cannot prevent this. It limits the damage: the key is not on disk in plaintext and is not kept in memory longer than needed, and after the incident the user can mark the key as compromised and rotate it.

### What D6 protects against

* Theft or copy of the keystore or of its backups (disk, USB, cloud folder).
* Offline brute force with strong passwords; precomputed tables (unique salts).
* Tampering with the keystore: metadata, KDF parameters, ciphertext, swapped keys, iteration downgrade.
* Using a key for the wrong purpose, or a retired, expired or compromised key.
* Accidental exposure of plaintext keys in the repository or demo files (the old `*_private.pem` files no longer exist).

### What D6 does NOT protect against (assumptions)

* A compromised endpoint (malware, keylogger, memory dump, root/admin access).
* Weak or reused passwords chosen despite the policy, or passwords disclosed by the user.
* A forgotten password (keys are unrecoverable by design).
* Python cannot securely wipe memory: objects may stay in RAM until garbage-collected.
* Attackers who delete keystores and backups (availability).
* Distribution of revocations to other users (there is no PKI or revocation server).

## 9. Automated tests

```bash
python -m unittest tests.test_key_management -v
```

The tests use 1,000 iterations only to run fast; the production default and minimum is 600,000.

| Required test | Test | What it checks |
|---|---|---|
| Correct password → access granted | `test_1_correct_password_access_granted` | The recovered key is identical to the original. |
| Wrong password → access denied | `test_2_wrong_password_access_denied` | `ValueError` and no key returned. |
| Modified keystore → failure | `test_3_modified_keystore_failure` | Ciphertext, tag, nonce, salt, key ID, key type, status, expiration, iterations or an extra field changed → rejected. |
| Backup → restore works | `test_4_backup_restore_works` | Backup, delete the original, restore with the password, same key. |
| Stolen keystore alone → cannot decrypt | `test_5_stolen_keystore_alone_cannot_decrypt` | The file has no plaintext key; password guesses fail; a file shared with Alice cannot be opened without her real key; with keystore + password it can. |

Extra tests (`TestKeyLifecycle`): KDF downgrade, default parameters, weak password rejected, unique salt/nonce, `0600` permissions, password asked with `getpass` and never stored, fingerprint and key identity (P-256 and Ed25519 = D5 `signer_id`), key-type mismatch, swapped ciphertext, password change, rotation (old files still open), compromised key refused, expiration, restore verifies the backup and does not overwrite by default.

## 10. Security discussion

**Why encrypt private keys?**
Because the private key is the root of all the other guarantees: whoever has Alice's P-256 key can unwrap the file key of every file shared with her (confidentiality, D3), and whoever has her Ed25519 key can sign as her (authenticity, D5). Disks, laptops and backups get lost or copied, so the system cannot rely on the storage being private. Encrypting the key turns "having the file" into "having the file **and** knowing the password".

**What happens if the password is weak?**
The protection is only as strong as the password. PBKDF2 makes every guess expensive and salts prevent precomputation, but a password from a dictionary can still be found with an offline attack, and then the private key and all files shared with it are exposed. That is why the system enforces a minimum length, recommends passphrases, and supports password change and key rotation.

**What are the system limitations?**
* It cannot protect against malware on the user's device or a user who reveals the password.
* PBKDF2 is not memory-hard (Argon2id would resist GPU attacks better; the format allows migrating, see §3).
* On Windows, `chmod 0600` only toggles the read-only flag; file access is controlled by the ACLs of the user profile, so the keystore folder must stay inside the user's home directory.
* Python cannot guarantee that the key is wiped from memory.
* Revocation and rotation are local and must be communicated out-of-band.
* Metadata (key ID, public key, dates, status) is readable without the password; it is authenticated, not encrypted.
* A forgotten password means the key and the files that depend on it are lost.

## 11. Hardening after the D6 review

| D6 feedback | Implementation | Tests (`tests/test_keystore_hardening.py`) |
|---|---|---|
| Complete key lifecycle | Rotation (`rotate_key`), revocation (`mark_compromised`), expiration (`expires_at`), password change, backup/restore. Revocation is also propagated to contacts through the trust store (see [`D5-Digital_Signatures.md`](D5-Digital_Signatures.md)). | `test_key_management.py` (`TestKeyLifecycle`) |
| `open(filepath, 'w')`: no permissions, can overwrite | Atomic write (`mkstemp` + `fsync`), `0600` permissions, and **no overwrite by default**: `encrypt_and_save_key(..., overwrite=False)` refuses an existing file; the final step is a hard link, which fails atomically if the destination exists. Rotation never overwrites an existing keystore. | `TestNoAccidentalOverwrite` |
| Metadata and KDF parameters not authenticated | The AAD is the whole header: format, version, **all metadata** and **all KDF parameters** (`_aad`). Any change makes unlocking fail. | `test_3_modified_keystore_failure` |
| KDF choice | Justified in §3 (PBKDF2 vs scrypt vs Argon2id). Iterations bounded: minimum 600,000 (downgrade) and maximum 10,000,000 (DoS). | `TestKdfParameterBounds` |
| Password policy | Length ≥ 12, common-password list, not only digits, ≥ 5 distinct characters, no simple sequences. | `TestPasswordPolicy` |
| Backup and recovery | Backups are verified byte-by-byte after copying and never overwrite each other. `restore_keystore(..., expected_fingerprint=...)` checks the password, integrity **and the identity of the key** before copying; nothing is written if any check fails. | `TestBackupAndRecovery` |
| Failure handling | Specific exceptions in `vault/errors.py`: `KeystoreFormatError` (malformed JSON, Base64, fields, KDF parameters, oversized files), `KeystoreAuthError` (wrong password / tampering), `KeystoreNotFoundError`, `KeystoreExistsError`, `WeakPasswordError`, `KeyRevokedError`, `KeyInactiveError`. All raised `from None`. | `TestMalformedKeystores` |

### Offline password-guessing threat

An attacker who copies a keystore file (stolen laptop, leaked backup) can try passwords **offline**, without any rate limit and without the application noticing. The cost per guess is 600,000 HMAC-SHA256 computations:

| Password | Guesses needed (worst case) | Time with 10⁶ guesses/s (GPU rig, PBKDF2 at 600k) |
|---|---|---|
| 8 lowercase letters (26⁸ ≈ 2×10¹¹) | 2×10¹¹ | ≈ 2.4 days |
| 12 lowercase letters (26¹² ≈ 9.5×10¹⁶) | 9.5×10¹⁶ | ≈ 3,000 years |
| 4 random common words (7,776⁴ ≈ 3.7×10¹⁵) | 3.7×10¹⁵ | ≈ 117 years |
| A password from a leaked-password list | ~10⁹ | ≈ 17 minutes |

The table (rough, order-of-magnitude figures) shows why the policy focuses on **length** and on rejecting **common** passwords: no KDF can save a password that is on a dictionary list, while a long passphrase is out of reach even for PBKDF2. The salt makes each keystore a separate target (no precomputed tables), and the maximum-iterations bound guarantees the attacker cannot turn the KDF against the user (DoS).
