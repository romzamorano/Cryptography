"""
D3 - Hybrid encryption: required tests.

1. File shared with 2 users        -> both can decrypt
2. Unauthorized user               -> cannot decrypt
3. Wrong private key               -> fails
4. Tampered recipient list         -> decryption fails
5. Removing a recipient entry      -> breaks access
"""
import unittest
import json
from cryptography.hazmat.primitives.asymmetric import ec
from vault.crypto_module import SecureEncryptionModule

class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        self.module = SecureEncryptionModule()
        self.plaintext = b"Top secret project information."

        # 1. Generate identities and (public/private) key pairs for 3 users
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.alice_pub = self.alice_priv.public_key()

        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_pub = self.bob_priv.public_key()

        self.eve_priv = ec.generate_private_key(ec.SECP256R1()) # Eve is the attacker
        self.eve_pub = self.eve_priv.public_key()

        # D5: Alice (sender) also has an Ed25519 key pair to sign
        self.alice_sign_priv, self.alice_sign_pub = SecureEncryptionModule.generate_signing_keypair()

        # 2. Authorized recipient list (Alice and Bob)
        self.recipients = [
            {"id": "Alice", "public_key": self.alice_pub},
            {"id": "Bob", "public_key": self.bob_pub}
        ]

    def _encrypt(self):
        return self.module.encrypt_file(self.plaintext, self.recipients,
                                        signer_private_key=self.alice_sign_priv)

    def test_1_shared_two_users_both_decrypt(self):
        """Requirement: file shared with 2 users -> both can decrypt."""
        container = self._encrypt()

        # Alice decrypts
        decrypted_alice = self.module.decrypt_file(container, self.alice_priv, "Alice", self.alice_sign_pub)
        self.assertEqual(self.plaintext, decrypted_alice)

        # Bob decrypts
        decrypted_bob = self.module.decrypt_file(container, self.bob_priv, "Bob", self.alice_sign_pub)
        self.assertEqual(self.plaintext, decrypted_bob)

    def test_2_unauthorized_user_cannot_decrypt(self):
        """Requirement: unauthorized user cannot decrypt."""
        container = self._encrypt()

        # Eve (not in the list) tries to decrypt with her own ID
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Eve", self.alice_sign_pub)

    def test_3_wrong_private_key_fails(self):
        """Requirement: wrong private key -> fails."""
        container = self._encrypt()

        # Eve impersonates Bob: she uses the ID "Bob" but her own private key
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Bob", self.alice_sign_pub)

    def test_4_tampered_recipient_list_fails(self):
        """Requirement: tampered recipient list -> decryption fails."""
        container = json.loads(self._encrypt())

        # The attacker edits the recipient list directly ("Bob" -> "Eve")
        for r in container["recipients"]:
            if r["id"] == "Bob":
                r["id"] = "Eve"
        tampered_container = json.dumps(container).encode("utf-8")

        # Alice tries to open it: the signature (and the AES-GCM AAD) detect the change
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice", self.alice_sign_pub)

    def test_5_removing_recipient_breaks_access(self):
        """Requirement: removing a recipient entry -> breaks access."""
        container = json.loads(self._encrypt())

        # The attacker removes "Bob" from the recipient list
        container["recipients"] = [r for r in container["recipients"] if r["id"] != "Bob"]
        tampered_container = json.dumps(container).encode("utf-8")

        # Even though Alice is still listed and her key is correct, the file is rejected
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice", self.alice_sign_pub)

if __name__ == '__main__':
    unittest.main()
