import unittest
import json
from cryptography.hazmat.primitives.asymmetric import ec
from vault.crypto_module import SecureEncryptionModule

class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        self.module = SecureEncryptionModule()
        self.plaintext = b"Informacion ultra secreta del proyecto."

        # 1. Generar identidades y pares de claves (Pública/Privada) para 3 usuarios
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.alice_pub = self.alice_priv.public_key()

        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_pub = self.bob_priv.public_key()

        self.eve_priv = ec.generate_private_key(ec.SECP256R1()) # Eve será nuestra atacante
        self.eve_pub = self.eve_priv.public_key()

        # D5: Alice (remitente) también tiene un par de llaves Ed25519 para firmar
        self.alice_sign_priv, self.alice_sign_pub = SecureEncryptionModule.generate_signing_keypair()

        # 2. Definir la lista de destinatarios autorizados (Alice y Bob)
        self.recipients = [
            {"id": "Alice", "public_key": self.alice_pub},
            {"id": "Bob", "public_key": self.bob_pub}
        ]

    def _encrypt(self):
        return self.module.encrypt_file(self.plaintext, self.recipients,
                                        signer_private_key=self.alice_sign_priv)

    def test_1_shared_two_users_both_decrypt(self):
        """Requisito: File shared with 2 users then both can decrypt."""
        container = self._encrypt()

        # Alice intenta descifrar
        decrypted_alice = self.module.decrypt_file(container, self.alice_priv, "Alice", self.alice_sign_pub)
        self.assertEqual(self.plaintext, decrypted_alice)

        # Bob intenta descifrar
        decrypted_bob = self.module.decrypt_file(container, self.bob_priv, "Bob", self.alice_sign_pub)
        self.assertEqual(self.plaintext, decrypted_bob)

    def test_2_unauthorized_user_cannot_decrypt(self):
        """Requisito: Unauthorized user cannot decrypt."""
        container = self._encrypt()

        # Eve (no está en la lista) intenta descifrar buscando su ID
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Eve", self.alice_sign_pub)

    def test_3_wrong_private_key_fails(self):
        """Requisito: Wrong private key then fails."""
        container = self._encrypt()

        # Eve intenta hacerse pasar por Bob usando el ID de "Bob", pero su propia clave privada
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Bob", self.alice_sign_pub)

    def test_4_tampered_recipient_list_fails(self):
        """Requisito: Tampered recipient list then decryption fails."""
        container = json.loads(self._encrypt())

        # El atacante altera directamente la lista de destinatarios (cambia "Bob" por "Eve")
        for r in container["recipients"]:
            if r["id"] == "Bob":
                r["id"] = "Eve"
        tampered_container = json.dumps(container).encode("utf-8")

        # Alice intenta abrirlo; la firma (y el AAD de AES-GCM) detectan la alteración
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice", self.alice_sign_pub)

    def test_5_removing_recipient_breaks_access(self):
        """Requisito: Removing a recipient entry then breaks access."""
        container = json.loads(self._encrypt())

        # El atacante elimina a "Bob" de la lista de destinatarios
        container["recipients"] = [r for r in container["recipients"] if r["id"] != "Bob"]
        tampered_container = json.dumps(container).encode("utf-8")

        # Aunque Alice sigue en la lista y su clave es correcta, el archivo es rechazado
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice", self.alice_sign_pub)

if __name__ == '__main__':
    unittest.main()
