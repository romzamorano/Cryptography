Deliverable 6

Key Management Design

KDF selection and parameters

To derive a strong symmetric encryption key from a user's password, our system uses PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256.

Iterations: 600,000 (aligned with modern OWASP recommendations).

Output length: 256 bits (32 bytes, required for AES-256).

Rationale: This high iteration count makes the key derivation computationally expensive. It intentionally slows down offline brute-force and dictionary attacks while keeping the delay (around a fraction of a second) acceptable for a legitimate user executing a cryptographic operation.

Key storage format

Private keys (P-256 for ECIES and Ed25519 for signatures) are never stored in plaintext. They are encrypted using AES-256-GCM and saved as a structured JSON object:

{
    "metadata": {
        "key_id": "Alice_P256",
        "key_type": "P-256",
        "encryption": "AES-256-GCM"
    },
    "kdf_parameters": {
        "algorithm": "PBKDF2HMAC-SHA256",
        "iterations": 600000,
        "salt": "<base64_string>"
    },
    "nonce": "<base64_string>",
    "encrypted_private_key": "<base64_string>",
    "tag": "<base64_string>"
}


Integrity constraint: The key_id is passed as Associated Data (AAD) into the AES-GCM cipher. If an attacker modifies the keystore (e.g., swapping or renaming keys), the AES-GCM tag verification will fail, and the system will reject the keystore.

Backup strategy

Because the encrypted private key and all necessary derivation parameters (like the salt, algorithm, and nonce) are self-contained within the JSON file, the backup strategy is straightforward. Users can safely back up their keys by copying the .json files to external drives or cloud storage. Restoration only requires access to the JSON file and the user's memorized password.

Security assumptions

Our key management design operates under two main assumptions:

Password secrecy: The user's password is memorized and never stored on the local disk or written in plaintext anywhere on the system.

Password complexity: The user chooses a strong, high-entropy password that cannot be easily guessed in a dictionary or brute-force attack.

Security Discussion

Why encrypt private keys?

If an attacker bypasses the secure vault and gains access to the local file system, discovering a plaintext private key means the entire system's security (AES-GCM, ECIES, Ed25519) instantly collapses. Encrypting the private keys shifts the security dependency from physical file possession to knowledge. Even if the keystore is stolen, the keys remain mathematically inaccessible without the user's password.

What happens if password is weak?

If a user chooses a weak password (e.g., "123456" or "password"), an attacker who steals the JSON keystore can easily perform an offline dictionary attack. Even though the 600,000 PBKDF2 iterations slow down the guessing process, the very low entropy of a weak password allows the attacker to guess it relatively quickly. Once guessed, they can derive the AES key, decrypt the private key, and completely break the vault's security.

What are our system limitations?

Our primary system limitation is that it relies entirely on the integrity of the local execution environment (the user's OS and RAM).

If the endpoint is compromised by active malware (such as a keylogger, rootkit, or memory scraper), the system cannot protect the keys.

An attacker could log the password as the user types it into the console, or dump the plaintext private key directly from RAM during the brief milliseconds it is decrypted for a cryptographic operation.

Conclusion: The system successfully protects against offline attacks and physical storage theft, but it cannot defend against a deeply compromised host endpoint.