import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureEncryptionModule:
    def __init__(self, key: bytes = None):
        # Genera una clave simétrica de 256 bits nueva si no se proporciona una
        if key is None:
            self.key = AESGCM.generate_key(bit_length=256)
        else:
            self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt_file(self, plaintext_bytes: bytes, filename: str = "archivo_seguro.txt") -> bytes:
        # Generar un nonce criptográficamente seguro de 96 bits (12 bytes)
        nonce = os.urandom(12)
        
        # 1. Definir y proteger los metadatos (Datos Autenticados Asociados - AAD)
        metadata = {
            "filename": filename,
            "algorithm_version": "AES-GCM-256 v1",
            "creation_timestamp": int(time.time())
        }
        aad = json.dumps(metadata).encode('utf-8')
        
        # 2. Encriptar el contenido y vincular los metadatos
        # AESGCM genera automáticamente el "Authentication Tag" y lo añade al final del ciphertext
        ciphertext = self.aesgcm.encrypt(nonce, plaintext_bytes, aad)
        
        # 3. Ensamblar el contenedor seguro
        # Estructura: [Tamaño del AAD (4 bytes)] + [AAD] + [Nonce (12 bytes)] + [Ciphertext + Tag]
        aad_length = len(aad).to_bytes(4, byteorder='big')
        secure_container = aad_length + aad + nonce + ciphertext
        
        return secure_container

    def decrypt_file(self, container_bytes: bytes) -> bytes:
        try:
            # 1. Desensamblar el contenedor
            aad_length = int.from_bytes(container_bytes[:4], byteorder='big')
            aad = container_bytes[4:4+aad_length]
            nonce = container_bytes[4+aad_length: 4+aad_length+12]
            ciphertext = container_bytes[4+aad_length+12:]
            
            # 2. Desencriptar y verificar integridad
            # Si un atacante modificó un solo bit del ciphertext, el nonce o el AAD,
            # cryptography lanzará una excepción InvalidTag.
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext
            
        except Exception:
            # Fallar de forma segura en caso de manipulación o clave incorrecta
            raise ValueError("Error de Autenticación: El archivo o los metadatos han sido alterados, o la clave es incorrecta.")