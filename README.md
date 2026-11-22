# Cryptography — Secure Digital Document Vault

This is the repository for the development of the Cryptography project.

<p align="center">
  <img src="https://media.giphy.com/media/077i6AULCXc0FKTj9s/giphy.gif" width="480" alt="Computer animation">
</p>

The team consists of:

* Carballo Ramírez Hanny
* Monter González Luis Enrique
* Siliano Haller Rodrigo
* Romero Zamorano Rosa Jennifer

---

## What it does

The **Secure Digital Document Vault** is a command-line application to send files securely between users over an **untrusted** shared folder or channel. Everything runs locally; the main program is an **interactive menu** (`vault_cli.py`) where every option is a use case.

* **Confidentiality (D2/D3):** each file is encrypted **once** with a fresh random 256-bit file key (**AES-256-GCM**). The file key is wrapped **separately for each recipient** with an ECIES-style construction (**ECDH P-256 + HKDF-SHA256 + AES-256-GCM**), bound to the recipient's key fingerprint and the protocol version.
* **Integrity and authenticity (D5):** the sender **signs** the whole package with **Ed25519**. The recipient verifies it with the key they **trust** for the expected sender **before** doing anything else, so modified, forged, re-signed or unsigned packages are rejected.
* **Recipient identity:** recipients are identified by the **SHA-256 fingerprint** of their public key, never by a self-declared name.
* **Trust, revocation and replay:** each user keeps a **trust store** of contacts (public keys confirmed by fingerprint, key-change detection, rotation and revocation) and a **replay cache** (packages already received are refused; packages older than 30 days are refused).
* **Key management (D6):** private keys are **never stored in plaintext**: they live in password-protected keystores (**PBKDF2-HMAC-SHA256**, 600,000 iterations + **AES-256-GCM**, whole header authenticated) with rotation, revocation, expiration and verified backup/restore.
* **Robustness:** every untrusted input is validated before use and every failure raises a specific error (`src/vault/errors.py`); recovered files are written with sanitized names, only inside the user's inbox and never overwriting.

## Architecture

![Hybrid Encryption Architecture](architecture_d3.png)

1. Alice encrypts the file with a fresh **file key** (AES-256-GCM) → ciphertext + authentication tag.
2. The file key is wrapped with ECIES for each recipient's **trusted** public key (identified by its fingerprint).
3. The package `{format, version, metadata, recipients, signer_id, nonce, ciphertext, tag, signature}` is **signed with Ed25519** and left in the **shared folder** (untrusted).
4. An attacker may read, modify, delete or re-deliver anything in the shared folder.
5. Bob checks the package structure, that the signer is a key he trusts for Alice, the signature, freshness and replay, finds **his** entry by the fingerprint of his key, unwraps the file key and decrypts. The file is written only if every check succeeds.

```text
vault_cli.py  ->  vault/cli.py (menu)  ->  vault/app.py (use cases)  ->  crypto_module.py   (AES-GCM, ECIES, Ed25519)
                                                                         keystore.py        (encrypted private keys)
                                       ->  vault/attack_lab.py           trust_store.py     (trusted contacts, revocation)
                                                                         replay_guard.py    (freshness, replay cache)
                                                                         errors.py          (specific exceptions)
```

The threat model, attack scenarios and traceability matrix are in [`D1_Architecture_Threat_Model.md`](D1_Architecture_Threat_Model.md).

## Documentation by deliverable

| Deliverable | Document |
|---|---|
| D1 — Architecture & Threat Model | [`D1_Architecture_Threat_Model.md`](D1_Architecture_Threat_Model.md) |
| D2 — Secure Symmetric Encryption Module | [`D2 - Secure Symmetric Encryption Module.md`](D2%20-%20Secure%20Symmetric%20Encryption%20Module.md) |
| D3 — Hybrid Encryption (multi-recipient) | [`D3-Hybrid_Encryption.md`](D3-Hybrid_Encryption.md) |
| D4 — Midterm System Presentation & Security Review | [Slides (Genially)](https://view.genially.com/6ae7e53c6fd0bfcb5d875c20) · Demo: [`examples/demo.py`](examples/demo.py) |
| D5 — Digital Signatures (+ trust, revocation, replay) | [`D5-Digital_Signatures.md`](D5-Digital_Signatures.md) |
| D6 — Secure Key Management | [`D6-Key_Management.md`](D6-Key_Management.md) |

## Repository structure

```text
Cryptography/
├── .github/workflows/python-tests.yml   # CI: runs all the tests on push / PR
├── vault_cli.py                         # MAIN PROGRAM: interactive menu
├── pyproject.toml                       # Project configuration (src layout)
├── requirements.txt                     # Dependencies + editable install of the project
├── scripts/                             # setup.(sh|bat), run_tests.(sh|bat)
├── examples/demo.py                     # Quick scripted demonstration (D4)
├── src/vault/
│   ├── cli.py                           # Menu: input/output only
│   ├── app.py                           # Use cases: users, contacts, send, receive, key lifecycle
│   ├── attack_lab.py                    # Attack scenarios shown step by step in the menu
│   ├── crypto_module.py                 # AES-256-GCM + ECIES (P-256) + Ed25519 container (v6)
│   ├── keystore.py                      # Password-protected keystores (PBKDF2 + AES-GCM)
│   ├── trust_store.py                   # Trusted contacts, public-key bundles, revocation
│   ├── replay_guard.py                  # Freshness window and replay cache
│   └── errors.py                        # Exception hierarchy (all are VaultError / ValueError)
├── tests/
│   ├── test_crypto.py                   # D3 hybrid encryption
│   ├── test_signatures.py               # D5 signatures
│   ├── test_ecies_validation.py         # Recipient fingerprints, capsule validation, malformed input
│   ├── test_key_management.py           # D6 keystore and lifecycle
│   ├── test_keystore_hardening.py       # No overwrite, KDF bounds, password policy, file errors
│   ├── test_trust_store.py              # Trust establishment, key change, rotation, revocation
│   ├── test_replay_guard.py             # Freshness window and replay cache
│   └── integration/                     # Several modules together, with real files
│       ├── _helpers.py
│       ├── test_file_sharing_flow.py
│       ├── test_attack_scenarios.py
│       ├── test_key_lifecycle_flow.py
│       ├── test_trust_and_replay_flow.py
│       ├── test_app_flow.py             # Every use case of the application
│       ├── test_attack_lab.py           # Every attack of the lab is blocked
│       └── test_cli_menu.py             # The menu driven with scripted keyboard input
├── architecture_d3.png
├── diagrama.png
└── README.md
```

---

## Instructions

### 1. Requirements

* Python 3.10 or newer
* Git (or download the repository as ZIP from GitHub)

### 2. Get the code

```bash
git clone https://github.com/romzamorano/Cryptography.git
cd Cryptography
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the program (interactive menu)

```bash
python vault_cli.py
```

Data is stored in `vault_home/` (ignored by Git). Use `python vault_cli.py --home other_folder` for a separate set of users.

```text
1. Users and keys            create a user, show keys/fingerprints, publish public keys, change password,
                             rotate a key, mark a key as compromised, replace it, back up, restore
2. Contacts                  import a contact's public keys (fingerprints shown and checked), list, revoke
3. Send a file               encrypt for trusted contacts, sign, leave the package in shared/
4. Receive / open a file     6 visible checks, then the file is saved in your inbox
5. Inspect a package         what anybody with access to the storage can see (not verified)
6. Attack lab                17 attacks from the threat model, each one shown step by step
7. Run the automated tests
```

**Typical first session**

1. *Users and keys → Create a user*: create `Alice` and `Bob` (passwords of at least 12 characters, not shown while typing).
2. *Contacts → Import*: as Alice, import `Bob.pub.json`; as Bob, import `Alice.pub.json`. Compare the fingerprints shown on screen.
3. *Send a file*: Alice chooses a file and Bob as recipient. The package appears in `vault_home/shared/`.
4. *Receive / open a file*: Bob chooses the package and Alice as expected sender. The six checks are shown and the file is saved in `vault_home/users/Bob/inbox/`.
5. *Receive* the same package again → **rejected as a replay**. *Inspect* it to see what an attacker can see.
6. *Attack lab → A*: runs every attack scenario in a separate sandbox and shows which defense stops each one.

### 5. Quick scripted demo

```bash
python examples/demo.py
```

A guided tour of the cryptography (encryption, sharing, tampering, signatures and key management) used in the D4 presentation. Press **Enter** to move between sections; it asks for a password for Alice, Bob and Eve (at least 12 characters). Each run starts from a clean `demo_files/` folder.

### 6. Run the tests

| What | Command | Tests |
|---|---|---|
| Everything (unit + integration) | `python -m unittest discover -s tests -v` | 168 |
| Only integration tests | `python -m unittest discover -s tests/integration -t . -v` | 64 |
| One file | `python -m unittest tests.test_trust_store -v` | — |

The same tests run automatically on GitHub Actions on every push and pull request to `main`. The tests use 1,000 PBKDF2 iterations only to run fast; the program always uses 600,000.

#### Unit tests (one module at a time)

| File | Verifies |
|---|---|
| `test_crypto.py` | Two recipients decrypt; non-recipient, wrong private key, tampered or removed recipient entries are rejected |
| `test_signatures.py` | Valid signature accepted; modified ciphertext/metadata/tag/nonce/recipients/signer, wrong key, removed signature, extra field and attacker re-signing rejected; signature verified **before** decrypting |
| `test_ecies_validation.py` | Recipient `key_id` = key fingerprint; expected fingerprint enforced; access decided by key, not name; capsules: truncated, invalid Base64, point not on the curve, modified ephemeral key / nonce / wrapped key / tag, capsule moved between recipients or files; malformed containers; errors without internal details; no plaintext on failure |
| `test_key_management.py` | Correct / wrong password, modified keystore, backup → restore, stolen keystore, KDF downgrade, rotation, compromise, expiration |
| `test_keystore_hardening.py` | No accidental overwrite; huge or corrupted KDF parameters; malformed JSON/Base64/fields; file errors; password policy; verified backups; restore checks the expected key |
| `test_trust_store.py` | Public-key bundles; expected fingerprints; key-change (substitution) detection; rotation keeps old keys as retired; revoked keys refused forever |
| `test_replay_guard.py` | Package accepted once; persistent cache; old and future packages rejected; pruning; corrupted cache does not disable the protection |

#### Integration tests (`tests/integration/`)

| File | Verifies |
|---|---|
| `test_file_sharing_flow.py` | End-to-end sharing with keystores and real files: identical output, no plaintext on disk, binary/large/empty files, three recipients, outsider rejected, a fresh container each time |
| `test_attack_scenarios.py` | Every field of a stored package modified on disk, corrupted/truncated files, Eve re-signing with her keystore key, file from another sender, stolen keystore, Eve's key on Bob's entry |
| `test_key_lifecycle_flow.py` | Rotation (old files still open), compromised and expired keys, backup → restore → old file opens, tampered backup, password change |
| `test_trust_and_replay_flow.py` | Trusted exchange, unknown sender, key substitution, fingerprint mismatch, revoked sender/recipient, sender rotation, replay, per-recipient cache, stale package, failed package not recorded |
| `test_app_flow.py` | Every use case of the menu: users, contacts, send/receive with the reported steps, nothing written on failure, replay and explicit re-open, path traversal, rotation, compromise and replacement, backup/restore, password change |
| `test_attack_lab.py` | All 17 attack-lab scenarios are blocked by the expected defense, before decryption |
| `test_cli_menu.py` | A full session typed into the menu: create users, exchange keys, send, receive, replay, inspect, invalid input, weak password, attack lab |

---

## Using the modules in your own code

```python
from cryptography.hazmat.primitives.asymmetric import ec
from vault.crypto_module import SecureEncryptionModule

vault = SecureEncryptionModule()
bob_priv = ec.generate_private_key(ec.SECP256R1())                       # encryption key (P-256)
alice_sign_priv, alice_sign_pub = vault.generate_signing_keypair()       # signing key (Ed25519)

container = vault.encrypt_file(
    b"secret data",
    recipients=[{"id": "Bob", "public_key": bob_priv.public_key()}],     # key_id = SHA-256 fingerprint
    filename="secret.txt",
    signer_private_key=alice_sign_priv,
)
plaintext = vault.decrypt_file(container, bob_priv, None, alice_sign_pub)   # verify, then decrypt
```

```python
from vault.app import VaultApp

app = VaultApp("vault_home")                        # the same use cases as the menu
app.create_user("Alice", "a long passphrase here")
```

See the deliverable documents for the format of the container, the keystore, the trust store and the security analysis.
