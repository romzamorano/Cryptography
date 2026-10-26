# Cryptography — Secure Digital Document Vault (Deliverable 3: Hybrid Encryption)

This is the repository for the development of the Cryptography project.

The team consists of:
* Carballo Ramírez Hanny
* Monter González Luis Enrique
* Siliano Haller Rodrigo
* Romero Zamorano Rosa Jennifer

---

## Overview

In **Deliverable 3 (D3)**, the **Secure Digital Document Vault** is extended to support **multi-recipient secure file sharing** using **Hybrid Encryption** (`AES-GCM-256 + ECIES(P-256)`). A file is encrypted only once with a freshly generated symmetric Data Encryption Key (DEK / `file_key`), while that key is individually encapsulated for each authorized recipient using their public key.

---

## Hybrid Design Explanation

### 1. Why Hybrid Encryption Is Used
Hybrid encryption combines the efficiency of symmetric cryptography (**AES-256-GCM**) with the flexible key distribution of asymmetric cryptography (**ECIES over SECP256R1 / P-256**). 
* Public-key cryptography eliminates the need for senders and recipients to pre-share a secret key over a secure channel; a sender only needs each recipient's public key.
* Symmetric cryptography provides high-speed Authenticated Encryption with Associated Data (**AEAD**) over the actual file payload.
* By combining both paradigms, the system achieves secure multi-user sharing without sacrificing performance or weakening confidentiality.

### 2. Why Symmetric Encryption Is Still Needed
Public-key primitives (such as RSA or elliptic curve operations) are mathematically intensive and orders of magnitude slower than symmetric ciphers. Furthermore, public-key schemes are strictly limited in the size of data they can directly operate on and are not designed for bulk data encryption. 
* Encrypting large files directly with public keys is computationally impractical and insecure.
* Instead, our module (`SecureEncryptionModule`) generates a random 256-bit symmetric `file_key` per file and uses **AES-256-GCM** to encrypt the file payload once in linear time, benefiting from hardware AES acceleration while generating a 128-bit authentication tag for integrity verification.

### 3. Why Per-Recipient Key Encryption Is Required
When sharing a document among $N$ authorized users (e.g., Alice and Bob), every recipient must be able to independently recover the `file_key` using only their own private key, without exposing the `file_key` to unauthorized parties or requiring recipients to share private keys with one another.
* Encrypting the file itself $N$ times would multiply storage and bandwidth costs by $N$.
* Instead, the file payload is encrypted **once** under the random 32-byte `file_key`.
* The 32-byte `file_key` is then independently wrapped for each recipient using **ECIES**: for each recipient, the sender generates a fresh ephemeral P-256 key pair, performs an **ECDH** key exchange with the recipient's public key, derives a 256-bit wrapping key via **HKDF-SHA256** (`info=b'ecies-key-wrap'`), and encrypts the `file_key` using **AES-256-GCM**.
* Only the holder of the corresponding recipient private key can compute the matching ECDH shared secret to unwrap their entry and recover the `file_key`.

---

## Security Decisions

### 1. How Recipients Identify Their Key
Each encrypted container embeds a deterministic JSON header containing a `recipients` array where every entry maps an explicit, unique user identifier (`id`) to that user's Base64-encoded ECIES key capsule (`encrypted_key`):

```json
{
  "metadata": {
    "algorithm": "AES-GCM-256 + ECIES(P-256)",
    "filename": "archivo.txt",
    "timestamp": 1761350000
  },
  "recipients": [
    {
      "id": "Alice",
      "encrypted_key": "<Base64 Alice ECIES Payload for>"
    },
    {
      "id": "Bob",
      "encrypted_key": "<Base64 Bob ECIES Payload for>"
    }
  ]
}
```

* **Deterministic Lookup & Uniqueness Enforcement:** During encryption (`encrypt_file`), the module validates that the recipient list is non-empty and enforces that all recipient `id` values are strictly unique (`len(recipient_ids) == len(set(recipient_ids))`), preventing key-confusion or shadowing attacks.
* During decryption (`decrypt_file`), the recipient supplies their `my_key_id` and private key. The module deterministically locates the matching `id` entry in `header_dict["recipients"]` and extracts the associated `encrypted_key` capsule. If the `id` is not present, access is immediately denied with a `ValueError`.

### 2. What Happens If an Attacker Modifies the Recipient List?
The entire JSON header—including `metadata` (filename, algorithm identifier, timestamp) and the full `recipients` list (`id` and `encrypted_key` for every user)—is canonically serialized with `json.dumps(..., sort_keys=True)` and passed as **Associated Authenticated Data (AAD)** into the file's **AES-256-GCM** encryption and decryption operations.
* If an attacker modifies a recipient `id` (e.g., replacing `"Bob"` with `"Eve"`), alters an `encrypted_key`, injects a new recipient, or deletes an existing recipient entry from the container header, the recomputed 128-bit GCM authentication tag will not match the tag attached to the ciphertext.
* `aesgcm.decrypt(nonce, ciphertext, aad)` immediately raises an authentication exception (`InvalidTag`, caught and raised as a `ValueError` integrity error), blocking access even for legitimate recipients whose own key entries were untouched.

### 3. What Happens If the Public or Private Key Is Wrong?
* **Wrong Private Key During Decryption (Impersonation Attempt):** If an unauthorized user (e.g., Eve) claims a legitimate recipient's identifier (e.g., `"Bob"`) but provides her own private key, the `ECDH` key exchange between Eve's private key and the sender's ephemeral public key yields a completely different shared secret. Consequently, `HKDF-SHA256` derives the wrong 256-bit wrapping key, and the inner `AESGCM.decrypt()` call inside `_ecies_decrypt_key` fails its authentication tag check. Decryption aborts immediately before the file ciphertext is ever touched.
* **Wrong Public Key During Encryption:** If a file is encrypted using an incorrect or mismatched public key for a recipient, the ECIES key capsule is bound to that wrong public key's mathematical point on the P-256 curve. When the intended recipient later attempts to open the container with their actual private key, the ECDH shared secret derivation will not match, causing `_ecies_decrypt_key` to fail authentication and safely reject decryption without leaking key material or plaintext.
* **Invalid Curve / Malformed Key:** Using a key from an incompatible curve or a corrupted public key fails during serialization/ECDH exchange, preventing weak or invalid key pairs from generating usable containers.

---

## Encrypted Container Binary Layout

```text
+-----------------------+-----------------------------------+-------------------+----------------------------------+
|  AAD Length (4 bytes) |       AAD JSON Header (N bytes)   | Nonce (12 bytes)  | Ciphertext + GCM Tag (M + 16 B)  |
|   Big-Endian UInt32   |  metadata + recipients (ECIES)    |  96-bit Random IV | AES-256-GCM Encrypted File + Tag |
+-----------------------+-----------------------------------+-------------------+----------------------------------+
```

Each recipient's `encrypted_key` (decoded from Base64) follows the binary ECIES structure:

```text
+----------------------------+---------------------------------+--------------------+----------------------------------+
| Ephemeral PubKey Len (2 B) | Ephemeral Public Key (DER)      | Wrap Nonce (12 B)  | Wrapped File Key + Tag (48 B)    |
|     Big-Endian UInt16      | SECP256R1 SubjectPublicKeyInfo  |  96-bit Random IV  | 32-Byte File Key + 16-Byte Tag   |
+----------------------------+---------------------------------+--------------------+----------------------------------+
```

---

## Repository Structure

```text
Cryptography/
├── .github/
│   └── workflows/
│       └── python-tests.yml   # Automated CI workflow running unit tests on push/PR
├── vault/
│   └── crypto_module.py       # Hybrid encryption engine (SecureEncryptionModule)
├── tests/
│   └── test_crypto.py         # Adversarial unit test suite for D3 requirements
├── requirements.txt           # Project dependencies (cryptography, pytest)
└── README.md                  # Project documentation and security analysis
```

---

## Running the Unit Tests

The test suite in `tests/test_crypto.py` verifies all 5 security requirements for Deliverable 3:
1. **`test_1_shared_two_users_both_decrypt`**: A file encrypted once for Alice and Bob can be decrypted independently by both.
2. **`test_2_unauthorized_user_cannot_decrypt`**: An unauthorized user (Eve) not in the recipient list is rejected.
3. **`test_3_wrong_private_key_fails`**: An attacker attempting to use Bob's ID with a different private key fails ECIES unwrapping.
4. **`test_4_tampered_recipient_list_fails`**: Modifying a recipient ID in the container header invalidates the AES-GCM AAD tag and aborts decryption.
5. **`test_5_removing_recipient_breaks_access`**: Removing a recipient entry from the header breaks AAD integrity and blocks access for all users.

Run the tests locally with:

```bash
python -m unittest discover -s tests -v
```