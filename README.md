# Cryptography — Secure Digital Document Vault

Secure File Exchange Platform developed for the Cryptography course (Group 04, Team 07).

<p align="center">
  <img src="https://media.giphy.com/media/077i6AULCXc0FKTj9s/giphy.gif" width="480" alt="Computer animation">
</p>

The team consists of:

* Carballo Ramírez Hanny
* Monter González Luis Enrique
* Siliano Haller Rodrigo
* Romero Zamorano Rosa Jennifer

---

## Project description

The **Secure Digital Document Vault** is a command-line application to exchange files securely between users over an **untrusted** shared folder or channel. Everything runs locally; the main program is an **interactive menu** (`vault_cli.py`) where every option is a use case. It integrates all the work of the course:

* **Secure symmetric encryption (D2):** each file is encrypted **once** with a fresh random 256-bit key (**AES-256-GCM**, random 96-bit nonce); the header is authenticated as **AAD**.
* **Hybrid encryption and sharing (D3):** the file key is wrapped **separately for each recipient** with an ECIES-style construction (**ECDH P-256 + HKDF-SHA256 + AES-256-GCM**). Recipients are identified by the **SHA-256 fingerprint** of their public key, and the key wrap is bound to the recipient and protocol version.
* **Signatures and authentication (D5):** the sender **signs** the whole package with **Ed25519**; the recipient verifies it with the key they **trust** for the expected sender **before** anything is decrypted. A trust store handles key confirmation, key changes and revocation, and a replay guard refuses old or repeated packages.
* **Key management (D6):** private keys live only in password-protected keystores (**PBKDF2-HMAC-SHA256**, 600,000 iterations + **AES-256-GCM**, whole header authenticated) with rotation, revocation, expiration and verified backup/restore.
* **Secure software practices:** strict input validation, fail-closed behavior, canonical serialization and specific error handling; recovered files are written with sanitized names, only inside the user's inbox and never overwriting.

## System architecture

![Hybrid Encryption Architecture](docs/images/architecture_d3.png)

1. Alice encrypts the file with a fresh **file key** (AES-256-GCM) → ciphertext + authentication tag.
2. The file key is wrapped with ECIES for each recipient's **trusted** public key (identified by its fingerprint).
3. The package `{format, version, metadata, recipients, signer_id, nonce, ciphertext, tag, signature}` is **signed with Ed25519** and left in the **shared folder** (untrusted).
4. An attacker may read, modify, delete or re-deliver anything in the shared folder.
5. Bob checks the package structure, that the signer is a key he trusts for Alice, the signature, freshness and replay, finds **his** entry by the fingerprint of his key, unwraps the file key and decrypts. The file is written only if every check succeeds.

```text
vault_cli.py -> src/vault/cli.py (menu) -> src/vault/app.py (use cases) -> crypto_module.py  (AES-GCM, ECIES, Ed25519)
                                                                         -> keystore.py       (encrypted private keys)
                                        -> src/vault/attack_lab.py       -> trust_store.py    (trusted contacts, revocation)
                                                                         -> replay_guard.py   (freshness, replay cache)
                                                                         -> errors.py         (specific exceptions)
```

**Trust boundaries:** each user's local environment (`vault_home/users/<name>/`: keystores, contacts, replay cache) is trusted; the shared folder (`vault_home/shared/`) and the published public keys (`vault_home/public/`) are not.

## Installation

Requirements: **Python 3.10 or newer** and Git (or the repository downloaded as ZIP).

```bash
git clone https://github.com/romzamorano/Cryptography.git
cd Cryptography
pip install -r requirements.txt
```

`requirements.txt` installs the only dependency (`cryptography`) and the project itself in editable mode (src layout, see `pyproject.toml`), so `import vault` works for the menu, the tests and the examples. On Windows use `py -m pip ...` if `pip` is not recognized.

Alternatively, the setup scripts create a virtual environment, install everything and run the tests:

```bash
sh scripts/setup.sh        # Linux / macOS
scripts\setup.bat          # Windows
```

## Usage examples

### Interactive menu (main program)

```bash
python vault_cli.py                     # data stored in ./vault_home (ignored by Git)
python vault_cli.py --home other_dir    # a separate set of users
```

```text
1. Users and keys            create a user, show keys/fingerprints, publish public keys, change password,
                             rotate a key, mark a key as compromised, replace it, back up, restore
2. Contacts                  import a contact's public keys (fingerprints shown and checked), list, revoke
3. Send a file               encrypt any file for trusted contacts, sign, leave the package in shared/
4. Receive / open a file     6 visible checks, then the file is saved in your inbox
5. Inspect a package         what anybody with access to the storage can see (not verified)
6. Attack lab                17 attacks from the threat model, each one shown step by step
7. Run the automated tests
```

**Typical session**

1. *Users and keys → Create a user*: create `Alice` and `Bob` (passwords of at least 12 characters, not shown while typing).
2. *Contacts → Import*: as Alice, import `Bob.pub.json`; as Bob, import `Alice.pub.json`, comparing the fingerprints with their owner.
3. *Send a file*: Alice chooses any file and Bob as recipient (several recipients: `1,2`). The package appears in `vault_home/shared/`.
4. *Receive / open a file*: Bob chooses the package and Alice as expected sender. The six checks are shown and the file is saved in `vault_home/users/Bob/inbox/`.
5. *Receive* the same package again → **rejected as a replay**. *Inspect* it to see what an attacker can see.
6. *Attack lab → A*: runs every attack scenario in a separate sandbox: `17/17 attacks blocked`.

### Exchanging files between two computers

This is the real scenario the system is designed for: each person runs the program on **their own computer**, and files travel through any **untrusted** channel (e-mail, chat, cloud drive, USB stick). Example with Alice (computer A) and Bob (computer B), both with the repository installed:

1. **Each person creates only their own user** (*Users and keys → Create a user*): Alice on computer A, Bob on computer B. Never create the other person's user: a private key must exist only on its owner's computer.
2. **Exchange public keys.** Alice sends Bob her file `vault_home/public/Alice.pub.json`, and Bob sends Alice `vault_home/public/Bob.pub.json`, by any channel. These files only contain public keys. **Never send anything from `vault_home/users/`**: it holds the (encrypted) private keys, the contacts and the inbox.
3. **Confirm the fingerprints through a different channel** (in person or by phone). Each one reads their signing fingerprint from *Users and keys → Show my keys and fingerprints* (`ed25519:...`). This step is what protects against somebody replacing the public-key file on the way.
4. **Import the other person's keys** (*Contacts → Import a contact's public keys → other file...*), give the path of the received `.pub.json` (drag the file into the terminal) and paste the signing fingerprint the owner dictated. A fingerprint that does not match is rejected.
5. **Alice sends the file** (*Send a file*: Alice → file → Bob). The package is created in `vault_home/shared/<file>.Alice.<date>.vault`. Alice sends **that `.vault` file** to Bob by any channel: whoever intercepts it can neither read it nor modify it without detection.
6. **Bob opens it** (*Receive / open a file* → Bob → *other file...* → path of the downloaded `.vault` → expected sender: Alice → his password). After the six checks, the file is saved in `vault_home/users/Bob/inbox/`.

Notes:

* Contact names come from the bundle (`Alice.pub.json` → contact `Alice`): use different user names on each computer.
* The clocks of both computers must be roughly correct: a package signed more than 5 minutes in the future or more than 30 days ago is rejected.
* Each package is accepted once per recipient; opening it again is detected as a possible replay and requires explicit confirmation.
* `vault_home/` is ignored by Git: do not use the repository to exchange keys or packages.
* If a contact rotates or replaces a key, they send the new `.pub.json`; importing it shows a *key changed* warning that is accepted only after confirming the new fingerprint.

### Quick scripted demo

```bash
python examples/demo.py
```

A guided tour of the cryptography (encryption, sharing, tampering, signatures and key management) used in the D4 presentation.

### Using the modules from Python

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

## Security assumptions

* Each user's device is trusted: it is free of malware, and users do not reveal their passwords.
* The operating system provides a cryptographically secure random number generator.
* Public keys are bound to their owners by comparing fingerprints through an independent channel (in person, phone call). A fingerprint identifies a key but does not, by itself, prove who owns it.
* The shared folder and the transfer channel are completely untrusted: anybody may read, modify, delete or re-deliver packages.
* The cryptographic primitives (AES-GCM, P-256, HKDF, Ed25519, SHA-256, PBKDF2) are not broken, and the `cryptography` library implements them correctly.
* Clocks of sender and recipient are roughly synchronized (within 5 minutes) for the freshness check.

## Known limitations

* No protection against malware on the user's device, or a user who reveals their password.
* Trust in public keys depends on manual fingerprint comparison; there is no PKI or certificate authority.
* Revocation is local: each user must revoke a compromised contact key in their own contacts.
* Availability is not protected: packages can be deleted from the shared folder.
* A legitimate recipient can forward the decrypted file.
* Package metadata (file name, recipients, dates) is visible: it is authenticated but not encrypted.
* PBKDF2 is not memory-hard (Argon2id would resist GPU attacks better; the keystore format allows migrating).
* Python cannot guarantee that keys are wiped from memory.
* On Windows, `chmod 0600` only toggles the read-only flag; access depends on the user profile ACLs.
* Files are encrypted in memory (maximum 100 MiB per file); packages older than 30 days are rejected.
* The system is a course project, not production-ready software.

## Documentation

| Document | Content |
|---|---|
| [`docs/FINAL_DOCUMENTATION.md`](docs/FINAL_DOCUMENTATION.md) | Complete documentation of the final system: architecture, threat model and traceability matrix, cryptographic design, canonicalization, data formats, workflows, key management, use cases, attack lab, testing, feedback addressed, limitations |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Security documentation: threat model summary, cryptographic design decisions, canonicalization strategy, key management strategy, security audit findings |
| [`docs/D1_Architecture_Threat_Model.md`](docs/D1_Architecture_Threat_Model.md) | D1 — Architecture & Threat Model |
| [`docs/D2 - Secure Symmetric Encryption Module.md`](docs/D2%20-%20Secure%20Symmetric%20Encryption%20Module.md) | D2 — Secure Symmetric Encryption Module |
| [`docs/D3-Hybrid_Encryption.md`](docs/D3-Hybrid_Encryption.md) | D3 — Hybrid Encryption (multi-recipient) |
| [Slides (Genially)](https://view.genially.com/6ae7e53c6fd0bfcb5d875c20) · [`examples/demo.py`](examples/demo.py) | D4 — Midterm System Presentation & Security Review |
| [`docs/D5-Digital_Signatures.md`](docs/D5-Digital_Signatures.md) | D5 — Digital Signatures (+ trust, revocation, replay) |
| [`docs/D6-Key_Management.md`](docs/D6-Key_Management.md) | D6 — Secure Key Management |

## Repository structure

```text
Cryptography/
├── .github/workflows/python-tests.yml   # CI: runs all the tests on Python 3.10-3.13
├── vault_cli.py                         # MAIN PROGRAM: interactive menu
├── pyproject.toml                       # Project configuration (src layout)
├── requirements.txt                     # Dependencies + editable install of the project
├── src/vault/
│   ├── cli.py                           # Menu: input/output only
│   ├── app.py                           # Use cases: users, contacts, send, receive, key lifecycle
│   ├── attack_lab.py                    # Attack scenarios shown step by step in the menu
│   ├── crypto_module.py                 # AES-256-GCM + ECIES (P-256) + Ed25519 container (v6)
│   ├── keystore.py                      # Password-protected keystores (PBKDF2 + AES-GCM)
│   ├── trust_store.py                   # Trusted contacts, public-key bundles, revocation
│   ├── replay_guard.py                  # Freshness window and replay cache
│   └── errors.py                        # Exception hierarchy (all are VaultError / ValueError)
├── tests/                               # Unit tests (one module at a time)
│   └── integration/                     # Integration tests (several modules, real files, the menu)
├── docs/                                # Final and security documentation, D1-D6, images
├── examples/                            # demo.py
├── scripts/                             # setup.(sh|bat), run_tests.(sh|bat)
└── README.md
```

## Tests

| What | Command | Tests |
|---|---|---|
| Everything (unit + integration) | `python -m unittest discover -s tests -v` | 168 |
| Only integration tests | `python -m unittest discover -s tests/integration -t . -v` | 64 |
| Without installing the project | `sh scripts/run_tests.sh` / `scripts\run_tests.bat` | 168 |

GitHub Actions runs every test on Python 3.10–3.13 on each push and pull request to `main`. The tests use 1,000 PBKDF2 iterations only to run fast; the program always uses 600,000. The catalog of every test is in [`docs/FINAL_DOCUMENTATION.md`](docs/FINAL_DOCUMENTATION.md#11-testing).

| File | Verifies |
|---|---|
| `test_crypto.py` | Hybrid encryption: two recipients decrypt; non-recipient, wrong key, tampered or removed recipient entries rejected |
| `test_signatures.py` | Signatures: tampering, wrong key, removed signature, attacker re-signing rejected; signature verified **before** decrypting |
| `test_ecies_validation.py` | Recipient fingerprints, capsule validation, context binding, malformed containers, no plaintext or internal details on failure |
| `test_key_management.py` | Keystore: passwords, tampering, backup/restore, stolen keystore, KDF downgrade, rotation, compromise, expiration |
| `test_keystore_hardening.py` | No overwrite, KDF bounds, malformed files, file errors, password policy, verified backups |
| `test_trust_store.py` | Trust establishment, key-change detection, rotation, revocation |
| `test_replay_guard.py` | Freshness window and replay cache |
| `integration/` | End-to-end sharing, attacks on stored packages, key lifecycle, trust and replay, every menu use case, the attack lab and the menu driven with scripted input |
