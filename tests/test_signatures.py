"""
D5 - Digital Signatures: required tests.

1. Valid signature      -> file accepted
2. Modified ciphertext  -> rejected
3. Modified metadata    -> rejected
4. Wrong public key     -> rejected
5. Signature removed    -> rejected
(+ extra tests: recipients, signer_id, forged signature, extra fields,
   and that the signature is verified BEFORE decrypting)
"""
import base64
import json
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec
from vault.crypto_module import SecureEncryptionModule
from vault.errors import ContainerFormatError, SignatureError


def flip_b64(value: str, index: int = 0) -> str:
    """Flips one bit of the decoded Base64 data and encodes it again."""
    raw = bytearray(base64.b64decode(value))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class TestDigitalSignatures(unittest.TestCase):

    def setUp(self):
        self.module = SecureEncryptionModule()
        self.plaintext = b"Document signed by Alice."

        # ENCRYPTION keys (P-256, D3)
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.recipients = [
            {"id": "Alice", "public_key": self.alice_priv.public_key()},
            {"id": "Bob", "public_key": self.bob_priv.public_key()},
        ]

        # SIGNING keys (Ed25519, D5)
        self.alice_sign_priv, self.alice_sign_pub = SecureEncryptionModule.generate_signing_keypair()
        self.eve_sign_priv, self.eve_sign_pub = SecureEncryptionModule.generate_signing_keypair()

        self.container_bytes = self.module.encrypt_file(
            self.plaintext, self.recipients, filename="report.txt",
            signer_private_key=self.alice_sign_priv)

    # --- helpers -----------------------------------------------------------
    def _load(self) -> dict:
        return json.loads(self.container_bytes)

    def _dump(self, container: dict) -> bytes:
        return json.dumps(container).encode("utf-8")

    def _bob_decrypts(self, container_bytes, sender_pub=None):
        return self.module.decrypt_file(container_bytes, self.bob_priv, "Bob",
                                        sender_pub or self.alice_sign_pub)

    # --- required tests ----------------------------------------------------
    def test_1_valid_signature_file_accepted(self):
        """Valid signature -> file accepted."""
        container = self.module.verify_container(self.container_bytes, self.alice_sign_pub)
        self.assertEqual(container["signer_id"],
                         SecureEncryptionModule.key_fingerprint(self.alice_sign_pub))
        self.assertEqual(self._bob_decrypts(self.container_bytes), self.plaintext)

    def test_2_modified_ciphertext_rejected(self):
        """Modified ciphertext -> rejected."""
        container = self._load()
        container["ciphertext"] = flip_b64(container["ciphertext"])
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

    def test_3_modified_metadata_rejected(self):
        """Modified metadata -> rejected."""
        container = self._load()
        container["metadata"]["filename"] = "fake_invoice.txt"
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

        container = self._load()
        container["metadata"]["timestamp"] += 3600
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

    def test_4_wrong_public_key_rejected(self):
        """Wrong public key -> rejected."""
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self.container_bytes, sender_pub=self.eve_sign_pub)

    def test_5_signature_removed_rejected(self):
        """Signature removed -> rejected."""
        container = self._load()
        del container["signature"]
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

        container = self._load()
        container["signature"] = ""
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

    # --- extra tests -------------------------------------------------------
    def test_6_modified_tag_or_nonce_rejected(self):
        for field in ("tag", "nonce"):
            container = self._load()
            container[field] = flip_b64(container[field])
            with self.assertRaises(SignatureError):
                self._bob_decrypts(self._dump(container))

    def test_7_modified_recipients_rejected(self):
        container = self._load()
        container["recipients"] = [r for r in container["recipients"] if r["id"] != "Alice"]
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

    def test_8_forged_container_resigned_by_attacker_rejected(self):
        """Eve modifies the file and re-signs it with HER key, pretending to be Alice."""
        container = self._load()
        container["metadata"]["filename"] = "malware.exe"
        container["signer_id"] = SecureEncryptionModule.key_fingerprint(self.eve_sign_pub)
        unsigned = {k: v for k, v in container.items() if k != "signature"}
        forged = self.eve_sign_priv.sign(self.module._signed_digest(unsigned))
        container["signature"] = base64.b64encode(forged).decode("ascii")
        # Bob expects a file from Alice -> rejected
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container))

    def test_9_modified_signer_id_rejected(self):
        container = self._load()
        container["signer_id"] = SecureEncryptionModule.key_fingerprint(self.eve_sign_pub)
        with self.assertRaises(SignatureError):
            self._bob_decrypts(self._dump(container), sender_pub=self.eve_sign_pub)

    def test_10_extra_unsigned_field_rejected(self):
        container = self._load()
        container["note"] = "field added by an attacker"
        with self.assertRaises(ContainerFormatError):
            self._bob_decrypts(self._dump(container))

    def test_11_signature_verified_before_decryption(self):
        """If the signature fails, ECIES and AES-GCM are NEVER reached."""
        container = self._load()
        container["ciphertext"] = flip_b64(container["ciphertext"])
        with mock.patch.object(self.module, "_ecies_decrypt_key") as ecies:
            with self.assertRaises(ValueError):
                self._bob_decrypts(self._dump(container))
            ecies.assert_not_called()


if __name__ == "__main__":
    unittest.main()
