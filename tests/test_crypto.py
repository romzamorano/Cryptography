import unittest
from vault.crypto_module import SecureEncryptionModule

class TestEncryptionModule(unittest.TestCase):

    def setUp(self):
        self.module = SecureEncryptionModule()
        self.plaintext = b"Contenido super secreto para el entregable D2."
        self.filename = "secreto.txt"

    def test_encrypt_decrypt_returns_identical(self):
        """Prueba: Encriptar y desencriptar devuelve el archivo original"""
        container = self.module.encrypt_file(self.plaintext, self.filename)
        decrypted = self.module.decrypt_file(container)
        self.assertEqual(self.plaintext, decrypted)

    def test_wrong_key_fails(self):
        """Prueba: Usar una clave diferente falla de forma segura"""
        container = self.module.encrypt_file(self.plaintext, self.filename)
        
        # Simulamos a un usuario distinto con otra clave
        wrong_module = SecureEncryptionModule()
        with self.assertRaises(ValueError):
            wrong_module.decrypt_file(container)

    def test_modified_ciphertext_fails(self):
        """Prueba: Si se altera el texto cifrado, el sistema rechaza el archivo (Tamper detection)"""
        container = self.module.encrypt_file(self.plaintext, self.filename)
        
        # Volteamos el último byte del contenedor (que pertenece al tag de autenticación)
        tampered_container = bytearray(container)
        tampered_container[-1] ^= 0x01 
        
        with self.assertRaises(ValueError):
            self.module.decrypt_file(bytes(tampered_container))

    def test_multiple_encryptions_produce_different_ciphertexts(self):
        """Prueba: Encriptar lo mismo dos veces produce contenedores distintos (por el Nonce)"""
        container1 = self.module.encrypt_file(self.plaintext, self.filename)
        container2 = self.module.encrypt_file(self.plaintext, self.filename)
        self.assertNotEqual(container1, container2)

    def test_modified_metadata_fails(self):
        """Prueba: Si se alteran los metadatos (AAD), el sistema rechaza el archivo"""
        container = self.module.encrypt_file(self.plaintext, self.filename)

        # El atacante cambia el nombre del archivo dentro del header (mismo tamaño)
        tampered_container = container.replace(b"secreto.txt", b"secreto.TXT")
        self.assertNotEqual(container, tampered_container)

        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container)

    def test_modified_ciphertext_body_fails(self):
        """Prueba: Si se voltea un bit dentro del ciphertext (no del tag), se rechaza"""
        container = self.module.encrypt_file(self.plaintext, self.filename)

        # Saltamos [tamaño AAD (4)] + [AAD] + [nonce (12)] para caer en el ciphertext
        aad_length = int.from_bytes(container[:4], byteorder='big')
        pos = 4 + aad_length + 12

        tampered_container = bytearray(container)
        tampered_container[pos] ^= 0x01

        with self.assertRaises(ValueError):
            self.module.decrypt_file(bytes(tampered_container))

if __name__ == '__main__':
    unittest.main()
