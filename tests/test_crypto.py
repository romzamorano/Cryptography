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
        
        # 2. Definir la lista de destinatarios autorizados (Alice y Bob)
        self.recipients = [
            {"id": "Alice", "public_key": self.alice_pub},
            {"id": "Bob", "public_key": self.bob_pub}
        ]

    def test_1_shared_two_users_both_decrypt(self):
        """Requisito: File shared with 2 users then both can decrypt."""
        container = self.module.encrypt_file(self.plaintext, self.recipients)
        
        # Alice intenta descifrar
        decrypted_alice = self.module.decrypt_file(container, self.alice_priv, "Alice")
        self.assertEqual(self.plaintext, decrypted_alice)
        
        # Bob intenta descifrar
        decrypted_bob = self.module.decrypt_file(container, self.bob_priv, "Bob")
        self.assertEqual(self.plaintext, decrypted_bob)

    def test_2_unauthorized_user_cannot_decrypt(self):
        """Requisito: Unauthorized user cannot decrypt."""
        container = self.module.encrypt_file(self.plaintext, self.recipients)
        
        # Eve (no está en la lista) intenta descifrar buscando su ID
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Eve")

    def test_3_wrong_private_key_fails(self):
        """Requisito: Wrong private key then fails."""
        container = self.module.encrypt_file(self.plaintext, self.recipients)
        
        # Eve intenta hacerse pasar por Bob usando el ID de "Bob", pero su propia clave privada
        with self.assertRaises(ValueError):
            self.module.decrypt_file(container, self.eve_priv, "Bob")

    def test_4_tampered_recipient_list_fails(self):
        """Requisito: Tampered recipient list then decryption fails."""
        container = self.module.encrypt_file(self.plaintext, self.recipients)
        
        # Desensamblamos el contenedor para extraer el AAD (el JSON)
        aad_length = int.from_bytes(container[:4], byteorder='big')
        aad = container[4:4+aad_length]
        rest_of_container = container[4+aad_length:]
        
        header_dict = json.loads(aad.decode('utf-8'))
        
        # El atacante altera directamente la lista de destinatarios (cambia "Bob" por "Eve")
        for r in header_dict["recipients"]:
            if r["id"] == "Bob":
                r["id"] = "Eve"
                
        # Reensamblamos el contenedor con la lista de destinatarios manipulada
        tampered_aad = json.dumps(header_dict, sort_keys=True).encode('utf-8')
        tampered_aad_len = len(tampered_aad).to_bytes(4, byteorder='big')
        tampered_container = tampered_aad_len + tampered_aad + rest_of_container
        
        # Alice intenta abrirlo; AES-GCM detecta la alteración en el AAD y bloquea el acceso
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice")

    def test_5_removing_recipient_breaks_access(self):
        """Requisito: Removing a recipient entry then breaks access."""
        container = self.module.encrypt_file(self.plaintext, self.recipients)
        
        # Desensamblamos el contenedor para extraer el AAD (el JSON)
        aad_length = int.from_bytes(container[:4], byteorder='big')
        aad = container[4:4+aad_length]
        rest_of_container = container[4+aad_length:]
        
        header_dict = json.loads(aad.decode('utf-8'))
        
        # El atacante elimina a "Bob" de la lista de destinatarios
        header_dict["recipients"] = [r for r in header_dict["recipients"] if r["id"] != "Bob"]
        
        # Reensamblamos el contenedor modificado
        tampered_aad = json.dumps(header_dict, sort_keys=True).encode('utf-8')
        tampered_aad_len = len(tampered_aad).to_bytes(4, byteorder='big')
        tampered_container = tampered_aad_len + tampered_aad + rest_of_container
        
        # Aunque Alice sigue en la lista y su clave es correcta, AES-GCM detectará 
        # que el diccionario de destinatarios cambió de tamaño/contenido y bloqueará el archivo.
        with self.assertRaises(ValueError):
            self.module.decrypt_file(tampered_container, self.alice_priv, "Alice")

if __name__ == '__main__':
    unittest.main()