import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

class SecureKeyStore:
    def __init__(self):
        # KDF parameters aligned with current security standards
        self.kdf_algorithm = "PBKDF2HMAC-SHA256"
        self.iterations = 600_000  # OWASP recommendation for PBKDF2
        self.key_length = 32       # 256 bits for AES-GCM

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a 256-bit symmetric key from the password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_and_save_key(self, private_key, password: str, key_id: str, key_type: str, filepath: str):
        """
        Encrypts a private key and saves it in a structured format (Keystore).
        key_type can be "P-256" (for ECIES) or "Ed25519" (for Signatures).
        """
        # 1. Serialize the private key to bytes (unencrypted at this stage, in PEM format)
        raw_priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 2. Generate Salt and derive the key using the password
        salt = os.urandom(16)
        derived_key = self._derive_key(password, salt)

        # 3. Encrypt the private key bytes with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        
        # AESGCM.encrypt in the cryptography library appends the Auth Tag to the end of the ciphertext
        encrypted_data = aesgcm.encrypt(nonce, raw_priv_bytes, associated_data=key_id.encode())

        # Separate ciphertext and tag for the JSON format
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        # 4. Build the Keystore container
        keystore_container = {
            "metadata": {
                "key_id": key_id,
                "key_type": key_type,
                "encryption": "AES-256-GCM"
            },
            "kdf_parameters": {
                "algorithm": self.kdf_algorithm,
                "iterations": self.iterations,
                "salt": base64.b64encode(salt).decode('utf-8')
            },
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "encrypted_private_key": base64.b64encode(ciphertext).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }

        # 5. Save to disk
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(keystore_container, f, indent=4)
        
        return keystore_container

    def load_and_decrypt_key(self, filepath: str, password: str):
        """
        Reads the Keystore, derives the key with the provided password, and decrypts the private key.
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            keystore = json.load(f)

        # 1. Extract parameters
        salt = base64.b64decode(keystore["kdf_parameters"]["salt"])
        nonce = base64.b64decode(keystore["nonce"])
        ciphertext = base64.b64decode(keystore["encrypted_private_key"])
        tag = base64.b64decode(keystore["tag"])
        key_id = keystore["metadata"]["key_id"]

        # 2. Derive the key with the entered password
        derived_key = self._derive_key(password, salt)

        # 3. Decrypt the private key
        aesgcm = AESGCM(derived_key)
        try:
            # Reconstruct the payload as expected by the cryptography library (ciphertext + tag)
            raw_priv_bytes = aesgcm.decrypt(
                nonce, 
                ciphertext + tag, 
                associated_data=key_id.encode()
            )
        except Exception:
            raise ValueError("Incorrect password or tampered Keystore (Integrity failure).")

        # 4. Load the bytes into a usable PrivateKey object
        return serialization.load_pem_private_key(raw_priv_bytes, password=None)