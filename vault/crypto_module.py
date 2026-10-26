import os
import json
import time
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class SecureEncryptionModule:
    def __init__(self):
        # En D3, la clave simétrica ya NO es global.
        # Se genera una nueva (File Key / DEK) por cada archivo.
        pass

    def _ecies_encrypt_key(self, recipient_public_key, file_key: bytes) -> str:
        """Helper: Cifra la clave del archivo (DEK) usando ECIES para un destinatario."""
        # 1. Generar clave efímera del remitente
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # 2. Derivar secreto compartido usando ECDH
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        
        # 3. Derivar clave simétrica para envolver la File Key (HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies-key-wrap'
        ).derive(shared_secret)
        
        # 4. Envolver (cifrar) la File Key con AES-GCM
        wrap_nonce = os.urandom(12)
        wrap_aesgcm = AESGCM(derived_key)
        wrapped_key = wrap_aesgcm.encrypt(wrap_nonce, file_key, b'')
        
        # 5. Serializar la clave pública efímera para enviarla
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 6. Estructura ECIES: [Tamaño PubKey 2 bytes] + [PubKey] + [Nonce 12] + [Wrapped Key]
        pub_len = len(ephemeral_pub_bytes).to_bytes(2, byteorder='big')
        ecies_payload = pub_len + ephemeral_pub_bytes + wrap_nonce + wrapped_key
        
        return base64.b64encode(ecies_payload).decode('utf-8')

    def _ecies_decrypt_key(self, my_private_key, encrypted_key_b64: str) -> bytes:
        """Helper: Descifra la clave del archivo (DEK) usando la clave privada del destinatario."""
        ecies_payload = base64.b64decode(encrypted_key_b64)
        
        # 1. Extraer componentes del payload
        pub_len = int.from_bytes(ecies_payload[:2], byteorder='big')
        ephemeral_pub_bytes = ecies_payload[2:2+pub_len]
        wrap_nonce = ecies_payload[2+pub_len : 2+pub_len+12]
        wrapped_key = ecies_payload[2+pub_len+12:]
        
        # 2. Reconstruir clave pública efímera del remitente
        ephemeral_public_key = serialization.load_der_public_key(ephemeral_pub_bytes)
        
        # 3. Derivar el mismo secreto compartido (ECDH)
        shared_secret = my_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # 4. Derivar la misma clave de envoltura (HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies-key-wrap'
        ).derive(shared_secret)
        
        # 5. Desenvolver (descifrar) la File Key original
        wrap_aesgcm = AESGCM(derived_key)
        return wrap_aesgcm.decrypt(wrap_nonce, wrapped_key, b'')

    def encrypt_file(self, plaintext_bytes: bytes, recipients: list, filename: str = "archivo.txt") -> bytes:
        """
        recipients es una lista de diccionarios:
        [{"id": "Alice", "public_key": <objeto_clave_publica>}, ...]
        """
        # Validación de destinatarios y determinismo de IDs
        if not recipients:
            raise ValueError("Debe especificarse al menos un destinatario.")
        recipient_ids = [r["id"] for r in recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise ValueError("Conflicto de identidad: Los IDs de los destinatarios deben ser únicos.")

        # REQUISITO D3: 1. Generar clave simétrica aleatoria (File Key)
        file_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        
        # REQUISITO D3: 3. Cifrar la File Key individualmente por destinatario
        encrypted_recipients = []
        for recipient in recipients:
            enc_key_b64 = self._ecies_encrypt_key(recipient["public_key"], file_key)
            encrypted_recipients.append({
                "id": recipient["id"], # REQUISITO D3: Key Identifier determinista
                "encrypted_key": enc_key_b64
            })
            
        # REQUISITO D3: 5. Integrar Metadatos + Destinatarios en el AAD
        header_dict = {
            "metadata": {
                "filename": filename,
                "algorithm": "AES-GCM-256 + ECIES(P-256)",
                "timestamp": int(time.time())
            },
            "recipients": encrypted_recipients
        }
        aad = json.dumps(header_dict, sort_keys=True).encode('utf-8')
        
        # REQUISITO D3: 2. Cifrar el archivo una sola vez
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)
        
        # REQUISITO D3: 4. Estructura final del contenedor
        aad_length = len(aad).to_bytes(4, byteorder='big')
        return aad_length + aad + nonce + ciphertext

    def decrypt_file(self, container_bytes: bytes, my_private_key, my_key_id: str) -> bytes:
        # 1. Desensamblar el contenedor
        aad_length = int.from_bytes(container_bytes[:4], byteorder='big')
        aad = container_bytes[4:4+aad_length]
        nonce = container_bytes[4+aad_length: 4+aad_length+12]
        ciphertext = container_bytes[4+aad_length+12:]
        
        header_dict = json.loads(aad.decode('utf-8'))
        
        # REQUISITO D3: Recipient-Based Decryption (Buscar mi ID)
        my_encrypted_key_b64 = None
        for recipient in header_dict["recipients"]:
            if recipient["id"] == my_key_id:
                my_encrypted_key_b64 = recipient["encrypted_key"]
                break
                
        if not my_encrypted_key_b64:
            raise ValueError("Acceso Denegado: Tu ID no está en la lista de destinatarios.")
            
        # 2. Descifrar la File Key usando mi clave privada (ECIES)
        try:
            file_key = self._ecies_decrypt_key(my_private_key, my_encrypted_key_b64)
        except Exception:
            raise ValueError("Acceso Denegado: Clave privada incorrecta o error de ECIES.")
        
        # 3. Descifrar el archivo y validar que el AAD (incluyendo destinatarios) no fue alterado
        aesgcm = AESGCM(file_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception:
            raise ValueError("Error de Integridad: El archivo, los metadatos o los destinatarios fueron manipulados.")