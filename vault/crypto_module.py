import os
import json
import time
import base64
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# D5: Formato del contenedor firmado
# ---------------------------------------------------------------------------
CONTAINER_FORMAT = "SDDV"            # Secure Digital Document Vault
CONTAINER_VERSION = 5                # D5: contenedor firmado
SIGNATURE_ALGORITHM = "Ed25519"
# Separación de dominio: la firma solo es válida como "firma de contenedor SDDV v5"
SIGNATURE_DOMAIN = b"SDDV-D5-container-signature-v1\x00"

NONCE_SIZE = 12      # bytes, AES-GCM
TAG_SIZE = 16        # bytes, AES-GCM (128 bits)
SIGNATURE_SIZE = 64  # bytes, Ed25519 (RFC 8032)

# Campos que DEBE tener el contenedor (ni más, ni menos)
REQUIRED_FIELDS = {
    "format", "version", "metadata", "recipients",
    "nonce", "ciphertext", "tag", "signer_id", "signature",
}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str, expected_len: int = None, field: str = "") -> bytes:
    """Decodificación Base64 estricta (RFC 4648): rechaza caracteres inválidos."""
    if not isinstance(text, str):
        raise ValueError(f"Contenedor inválido: el campo '{field}' no es Base64.")
    try:
        data = base64.b64decode(text, validate=True)
    except Exception:
        raise ValueError(f"Contenedor inválido: el campo '{field}' no es Base64 válido.")
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(f"Contenedor inválido: longitud incorrecta en '{field}'.")
    return data


def _canonical_json(obj) -> bytes:
    """Serialización determinista: mismas llaves ordenadas, sin espacios, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _reject_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("Contenedor inválido: llaves JSON duplicadas.")
    return dict(pairs)


class SecureEncryptionModule:
    def __init__(self):
        # En D3, la clave simétrica ya NO es global.
        # Se genera una nueva (File Key / DEK) por cada archivo.
        pass

    # =======================================================================
    # D5: Identidad del firmante
    # =======================================================================
    @staticmethod
    def generate_signing_keypair():
        """Genera un par de llaves Ed25519 para FIRMAR (separado del par P-256 de cifrado)."""
        priv = Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def key_fingerprint(public_key) -> str:
        """
        signer_id = "ed25519:" + SHA-256(llave pública Ed25519 cruda de 32 bytes) en hex.
        Es un identificador determinista que se puede comparar contra la llave confiable.
        """
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("La llave del firmante debe ser una llave pública Ed25519.")
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return "ed25519:" + hashlib.sha256(raw).hexdigest()

    # =======================================================================
    # D5: Qué se firma
    # =======================================================================
    @staticmethod
    def _aad_from_container(container: dict) -> bytes:
        """AAD de AES-GCM: todos los metadatos relevantes para la seguridad."""
        return _canonical_json({
            "format": container["format"],
            "version": container["version"],
            "metadata": container["metadata"],
            "recipients": container["recipients"],
            "signer_id": container["signer_id"],
        })

    @staticmethod
    def _signed_digest(container: dict) -> bytes:
        """
        Datos firmados = TODOS los campos del contenedor excepto 'signature':
        format, version, metadata, recipients, nonce, ciphertext, tag, signer_id.
        1) Se serializan de forma canónica.
        2) Se calcula SHA-256 (hash).
        3) Se antepone la etiqueta de dominio. Esto es lo que se firma con Ed25519.
        """
        signed_fields = {k: v for k, v in container.items() if k != "signature"}
        digest = hashlib.sha256(_canonical_json(signed_fields)).digest()
        return SIGNATURE_DOMAIN + digest

    # =======================================================================
    # Hybrid encryption (D3) — sin cambios
    # =======================================================================
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

    # =======================================================================
    # D5: Encrypt -> Add metadata -> Sign -> Store
    # =======================================================================
    def encrypt_file(self, plaintext_bytes: bytes, recipients: list, filename: str = "archivo.txt",
                     *, signer_private_key) -> bytes:
        """
        recipients es una lista de diccionarios:
        [{"id": "Alice", "public_key": <objeto_clave_publica P-256>}, ...]
        signer_private_key: llave privada Ed25519 del remitente (quien crea el archivo).
        """
        if not isinstance(signer_private_key, Ed25519PrivateKey):
            raise ValueError("Se requiere la llave privada Ed25519 del remitente para firmar.")

        # Validación de destinatarios y determinismo de IDs
        if not recipients:
            raise ValueError("Debe especificarse al menos un destinatario.")
        recipient_ids = [r["id"] for r in recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise ValueError("Conflicto de identidad: Los IDs de los destinatarios deben ser únicos.")

        # D3: 1. Generar clave simétrica aleatoria (File Key)
        file_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_SIZE)

        # D3: 3. Cifrar la File Key individualmente por destinatario
        encrypted_recipients = []
        for recipient in recipients:
            enc_key_b64 = self._ecies_encrypt_key(recipient["public_key"], file_key)
            encrypted_recipients.append({
                "id": recipient["id"],
                "encrypted_key": enc_key_b64
            })

        # D5: Identificador del firmante (fingerprint de su llave pública)
        signer_id = self.key_fingerprint(signer_private_key.public_key())

        # Metadatos + destinatarios + firmante -> AAD
        container = {
            "format": CONTAINER_FORMAT,
            "version": CONTAINER_VERSION,
            "metadata": {
                "filename": filename,
                "algorithm": "AES-GCM-256 + ECIES(P-256)",
                "signature_algorithm": SIGNATURE_ALGORITHM,
                "timestamp": int(time.time())
            },
            "recipients": encrypted_recipients,
            "signer_id": signer_id,
        }
        aad = self._aad_from_container(container)

        # 1) ENCRYPT: cifrar el archivo una sola vez
        sealed = AESGCM(file_key).encrypt(nonce, plaintext_bytes, aad)
        ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]

        # 2) ADD METADATA: agregar nonce, ciphertext y tag al contenedor
        container["nonce"] = _b64e(nonce)
        container["ciphertext"] = _b64e(ciphertext)
        container["tag"] = _b64e(tag)

        # 3) SIGN: hash (SHA-256) de todo lo anterior y firma Ed25519
        signature = signer_private_key.sign(self._signed_digest(container))
        container["signature"] = _b64e(signature)

        # 4) STORE: contenedor serializado como JSON
        return json.dumps(container, sort_keys=True, indent=2).encode("utf-8")

    # =======================================================================
    # D5: Verificación (SIEMPRE antes de descifrar)
    # =======================================================================
    def verify_container(self, container_bytes: bytes, sender_public_key) -> dict:
        """
        1. Leer contenedor  2. Extraer metadatos + ciphertext  3. Verificar firma
        Regresa el contenedor (dict) si la firma es válida; si no, lanza ValueError.
        """
        # 1. Leer el contenedor
        try:
            container = json.loads(container_bytes.decode("utf-8"),
                                   object_pairs_hook=_reject_duplicate_keys)
        except ValueError as e:
            if "duplicadas" in str(e):
                raise
            raise ValueError("Contenedor inválido: no es un JSON válido.")
        except Exception:
            raise ValueError("Contenedor inválido: no es un JSON válido.")
        if not isinstance(container, dict):
            raise ValueError("Contenedor inválido: estructura incorrecta.")

        # 2. Extraer campos: deben estar TODOS (incluida la firma) y no puede haber extras
        missing = REQUIRED_FIELDS - container.keys()
        if "signature" in missing or not container.get("signature"):
            raise ValueError("Firma Rechazada: el contenedor no está firmado.")
        if missing:
            raise ValueError(f"Contenedor inválido: faltan campos {sorted(missing)}.")
        extra = container.keys() - REQUIRED_FIELDS
        if extra:
            raise ValueError(f"Contenedor inválido: campos no autenticados {sorted(extra)}.")
        if container["format"] != CONTAINER_FORMAT or container["version"] != CONTAINER_VERSION:
            raise ValueError("Contenedor inválido: formato o versión no soportados.")
        if not isinstance(container["metadata"], dict) or not isinstance(container["recipients"], list):
            raise ValueError("Contenedor inválido: estructura incorrecta.")

        # 3a. ¿El firmante declarado es el que esperamos? (llave pública confiable)
        expected_id = self.key_fingerprint(sender_public_key)
        if container["signer_id"] != expected_id:
            raise ValueError("Firma Rechazada: el firmante no coincide con la llave pública confiable.")

        # 3b. Verificar la firma Ed25519 sobre el hash de los datos firmados
        signature = _b64d(container["signature"], SIGNATURE_SIZE, "signature")
        try:
            sender_public_key.verify(signature, self._signed_digest(container))
        except InvalidSignature:
            raise ValueError("Firma Rechazada: el archivo o sus metadatos fueron modificados, o la firma es falsa.")

        return container

    def decrypt_file(self, container_bytes: bytes, my_private_key, my_key_id: str,
                     sender_public_key) -> bytes:
        # 1-3. Verificar la firma ANTES de tocar cualquier cosa criptográfica
        container = self.verify_container(container_bytes, sender_public_key)
        # 4. Firma válida -> continuar con el descifrado (D3)

        nonce = _b64d(container["nonce"], NONCE_SIZE, "nonce")
        ciphertext = _b64d(container["ciphertext"], None, "ciphertext")
        tag = _b64d(container["tag"], TAG_SIZE, "tag")
        aad = self._aad_from_container(container)

        # Recipient-Based Decryption (Buscar mi ID)
        my_encrypted_key_b64 = None
        for recipient in container["recipients"]:
            if recipient.get("id") == my_key_id:
                my_encrypted_key_b64 = recipient.get("encrypted_key")
                break

        if not my_encrypted_key_b64:
            raise ValueError("Acceso Denegado: Tu ID no está en la lista de destinatarios.")

        # Descifrar la File Key usando mi clave privada (ECIES)
        try:
            file_key = self._ecies_decrypt_key(my_private_key, my_encrypted_key_b64)
        except Exception:
            raise ValueError("Acceso Denegado: Clave privada incorrecta o error de ECIES.")

        # Descifrar el archivo y validar el AAD (segunda capa de integridad)
        try:
            return AESGCM(file_key).decrypt(nonce, ciphertext + tag, aad)
        except Exception:
            raise ValueError("Error de Integridad: El archivo, los metadatos o los destinatarios fueron manipulados.")
