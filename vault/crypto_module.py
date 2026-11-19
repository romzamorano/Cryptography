"""
Secure Digital Document Vault - cryptographic core (D2 + D3 + D5).

  * D2  AES-256-GCM encrypts the file with a fresh random file key (DEK), once.
  * D3  The DEK is wrapped for every recipient with an ECIES-style construction:
        ephemeral P-256 key -> ECDH -> HKDF-SHA256 -> AES-256-GCM (key-encryption key, KEK).
        Recipients are identified by the SHA-256 fingerprint of their public key.
  * D5  The whole container is signed with Ed25519 and the signature is verified
        BEFORE any key unwrapping or decryption.

Every error is a subclass of vault.errors.VaultError (which is a ValueError).
"""
import base64
import binascii
import hashlib
import json
import os
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.errors import (AccessDeniedError, ContainerFormatError, IntegrityError,
                          RecipientError, SignatureError)

# ---------------------------------------------------------------------------
# Container format (version 6: recipients identified by key fingerprint,
# fixed-size ECIES capsules with context binding)
# ---------------------------------------------------------------------------
CONTAINER_FORMAT = "SDDV"            # Secure Digital Document Vault
CONTAINER_VERSION = 6
FILE_ALGORITHM = "AES-256-GCM"
KEY_WRAP_ALGORITHM = "ECIES-P256-HKDF-SHA256-AES-256-GCM"
SIGNATURE_ALGORITHM = "Ed25519"
# Domain separation: a signature is only valid as an "SDDV v6 container signature"
SIGNATURE_DOMAIN = b"SDDV-container-signature-v6\x00"
# Domain separation of the key-wrapping step (HKDF info / AES-GCM AAD prefix)
KEY_WRAP_DOMAIN = b"SDDV-v6/dek-wrap/"

FILE_KEY_SIZE = 32   # bytes, AES-256 file key (DEK)
NONCE_SIZE = 12      # bytes, AES-GCM
TAG_SIZE = 16        # bytes, AES-GCM (128 bits)
SIGNATURE_SIZE = 64  # bytes, Ed25519 (RFC 8032)
P256_POINT_SIZE = 65  # bytes, uncompressed X9.62 point: 0x04 || X (32) || Y (32)
CAPSULE_SIZE = P256_POINT_SIZE + NONCE_SIZE + FILE_KEY_SIZE + TAG_SIZE   # 125 bytes

MAX_LABEL_LENGTH = 128
MAX_RECIPIENTS = 256

# Fields that the container MUST have (no more, no less)
REQUIRED_FIELDS = {
    "format", "version", "metadata", "recipients",
    "nonce", "ciphertext", "tag", "signer_id", "signature",
}
REQUIRED_METADATA = {"filename", "algorithm", "key_wrap", "signature_algorithm", "timestamp"}
REQUIRED_RECIPIENT_FIELDS = {"id", "key_id", "encrypted_key"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text, expected_len: int = None, field: str = "") -> bytes:
    """Strict Base64 decoding (RFC 4648): rejects invalid characters and wrong lengths."""
    if not isinstance(text, str):
        raise ContainerFormatError(f"Invalid container: field '{field}' is not Base64.")
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ContainerFormatError(f"Invalid container: field '{field}' is not valid Base64.") from None
    if expected_len is not None and len(data) != expected_len:
        raise ContainerFormatError(f"Invalid container: wrong length in '{field}'.")
    return data


def _canonical_json(obj) -> bytes:
    """Deterministic serialization: sorted keys, no spaces, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _reject_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ContainerFormatError("Invalid container: duplicated JSON keys.")
    return dict(pairs)


def _is_p256_public(key) -> bool:
    return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)


def _is_p256_private(key) -> bool:
    return isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)


class SecureEncryptionModule:
    """Hybrid encryption + signatures. Stateless: a fresh file key is generated per file."""

    # =======================================================================
    # Key identities (fingerprints)
    # =======================================================================
    @staticmethod
    def generate_signing_keypair():
        """Ed25519 key pair for SIGNING (separate from the P-256 encryption key pair)."""
        priv = Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def key_fingerprint(public_key) -> str:
        """
        Deterministic key identifier = SHA-256 of the canonical public-key encoding:
          * Ed25519 -> "ed25519:" + SHA-256(raw 32-byte public key)
          * P-256   -> "p256:"    + SHA-256(uncompressed X9.62 point, 65 bytes)
        A fingerprint IDENTIFIES a key; it does not prove who owns it (that requires
        an authentic out-of-band exchange, see the trust store).
        """
        if isinstance(public_key, Ed25519PublicKey):
            raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return "ed25519:" + hashlib.sha256(raw).hexdigest()
        if _is_p256_public(public_key):
            raw = public_key.public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint)
            return "p256:" + hashlib.sha256(raw).hexdigest()
        raise RecipientError("Unsupported key: only P-256 and Ed25519 public keys are allowed.")

    # =======================================================================
    # What is authenticated / signed
    # =======================================================================
    @staticmethod
    def _aad_from_container(container: dict) -> bytes:
        """AES-GCM AAD of the file: every security-relevant header field."""
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
        Signed data = ALL container fields except 'signature', serialized canonically,
        hashed with SHA-256 and prefixed with the domain-separation label.
        """
        signed_fields = {k: v for k, v in container.items() if k != "signature"}
        digest = hashlib.sha256(_canonical_json(signed_fields)).digest()
        return SIGNATURE_DOMAIN + digest

    # =======================================================================
    # ECIES-style key wrapping (D3)
    # =======================================================================
    @staticmethod
    def _wrap_context(recipient_key_id: str, ephemeral_point: bytes) -> bytes:
        """
        Context bound to the key wrapping: protocol label + version, recipient key
        fingerprint and the ephemeral public key. It is used as HKDF 'info' and as the
        AAD of the AES-GCM that protects the DEK, so a capsule cannot be reused for
        another recipient, another protocol version or with another ephemeral key.
        """
        return KEY_WRAP_DOMAIN + recipient_key_id.encode("ascii") + b"/" + ephemeral_point

    @classmethod
    def _derive_kek(cls, shared_secret: bytes, context: bytes) -> bytes:
        """Key-encryption key (KEK) derived from the ECDH shared secret. It is NOT the file key."""
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(shared_secret)

    def _ecies_encrypt_key(self, recipient_public_key, file_key: bytes, recipient_key_id: str) -> str:
        """Wraps the DEK for one recipient. Capsule = ephemeral point (65) || nonce (12) || wrapped DEK + tag (48)."""
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_point = ephemeral_private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        context = self._wrap_context(recipient_key_id, ephemeral_point)
        kek = self._derive_kek(shared_secret, context)

        wrap_nonce = os.urandom(NONCE_SIZE)
        wrapped_key = AESGCM(kek).encrypt(wrap_nonce, file_key, context)
        return _b64e(ephemeral_point + wrap_nonce + wrapped_key)

    @staticmethod
    def _parse_capsule(encrypted_key_b64):
        """Strict validation of the capsule BEFORE any cryptographic operation."""
        capsule = _b64d(encrypted_key_b64, CAPSULE_SIZE, "encrypted_key")
        ephemeral_point = capsule[:P256_POINT_SIZE]
        wrap_nonce = capsule[P256_POINT_SIZE:P256_POINT_SIZE + NONCE_SIZE]
        wrapped_key = capsule[P256_POINT_SIZE + NONCE_SIZE:]
        if ephemeral_point[0] != 0x04:
            raise ContainerFormatError("Invalid container: ephemeral key is not an uncompressed P-256 point.")
        try:
            # Also checks that the point is on the P-256 curve (invalid-curve attacks)
            ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_point)
        except ValueError:
            raise ContainerFormatError("Invalid container: ephemeral key is not a valid P-256 point.") from None
        return ephemeral_public_key, ephemeral_point, wrap_nonce, wrapped_key

    def _ecies_decrypt_key(self, my_private_key, encrypted_key_b64: str, recipient_key_id: str) -> bytes:
        """Unwraps the DEK with the recipient's private key."""
        ephemeral_public_key, ephemeral_point, wrap_nonce, wrapped_key = self._parse_capsule(encrypted_key_b64)
        shared_secret = my_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        context = self._wrap_context(recipient_key_id, ephemeral_point)
        kek = self._derive_kek(shared_secret, context)
        try:
            return AESGCM(kek).decrypt(wrap_nonce, wrapped_key, context)
        except InvalidTag:
            raise IntegrityError("Integrity error: the file key could not be unwrapped.") from None

    # =======================================================================
    # Encrypt -> add metadata -> sign -> store
    # =======================================================================
    def _prepare_recipients(self, recipients):
        """Validates the recipient list and computes each key fingerprint."""
        if not isinstance(recipients, (list, tuple)) or not recipients:
            raise RecipientError("At least one recipient is required.")
        if len(recipients) > MAX_RECIPIENTS:
            raise RecipientError(f"Too many recipients (maximum {MAX_RECIPIENTS}).")
        prepared = []
        for r in recipients:
            if not isinstance(r, dict) or "public_key" not in r:
                raise RecipientError("Each recipient must be a dict with a 'public_key'.")
            public_key = r["public_key"]
            if not _is_p256_public(public_key):
                raise RecipientError("Recipient keys must be P-256 public keys.")
            key_id = self.key_fingerprint(public_key)
            expected = r.get("fingerprint")
            if expected is not None and expected != key_id:
                raise RecipientError(
                    f"Recipient '{r.get('id', key_id)}': public key does not match the expected fingerprint.")
            label = r.get("id", key_id)
            if not isinstance(label, str) or not label or len(label) > MAX_LABEL_LENGTH:
                raise RecipientError("Recipient 'id' must be a non-empty string (max 128 characters).")
            prepared.append((label, key_id, public_key))

        if len({label for label, _, _ in prepared}) != len(prepared):
            raise RecipientError("Recipient ids must be unique.")
        if len({key_id for _, key_id, _ in prepared}) != len(prepared):
            raise RecipientError("The same public key appears twice in the recipient list.")
        return prepared

    def encrypt_file(self, plaintext_bytes: bytes, recipients: list, filename: str = "file.bin",
                     *, signer_private_key, timestamp: int = None) -> bytes:
        """
        recipients: [{"id": "Bob", "public_key": <P-256 public key>, "fingerprint": "p256:..." (optional)}, ...]
          * 'id' is a human-readable label (signed, but NOT used to decide access).
          * The recipient is identified by key_id = fingerprint of its public key.
          * If 'fingerprint' is given (e.g. from the trust store), the key must match it.
        signer_private_key: sender's Ed25519 private key.
        timestamp (optional): signing time (Unix seconds). Defaults to now; only tests and the
        attack lab set it, to simulate packages that were genuinely signed in the past.
        """
        if not isinstance(signer_private_key, Ed25519PrivateKey):
            raise SignatureError("The sender's Ed25519 private key is required to sign.")
        if not isinstance(plaintext_bytes, (bytes, bytearray)):
            raise ContainerFormatError("The plaintext must be bytes.")
        if not isinstance(filename, str) or not filename or len(filename) > 255:
            raise ContainerFormatError("The filename must be a non-empty string (max 255 characters).")
        prepared = self._prepare_recipients(recipients)
        if timestamp is None:
            timestamp = int(time.time())
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
            raise ContainerFormatError("The timestamp must be a non-negative integer.")

        # D2: a fresh random file key (DEK) per file -> each DEK encrypts exactly ONE message
        file_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_SIZE)

        # D3: the DEK is wrapped separately for every recipient
        encrypted_recipients = [
            {"id": label, "key_id": key_id,
             "encrypted_key": self._ecies_encrypt_key(public_key, file_key, key_id)}
            for label, key_id, public_key in prepared
        ]

        container = {
            "format": CONTAINER_FORMAT,
            "version": CONTAINER_VERSION,
            "metadata": {
                "filename": filename,
                "algorithm": FILE_ALGORITHM,
                "key_wrap": KEY_WRAP_ALGORITHM,
                "signature_algorithm": SIGNATURE_ALGORITHM,
                "timestamp": timestamp,
            },
            "recipients": encrypted_recipients,
            "signer_id": self.key_fingerprint(signer_private_key.public_key()),
        }

        # 1) ENCRYPT the file once (header authenticated as AAD)
        sealed = AESGCM(file_key).encrypt(nonce, bytes(plaintext_bytes), self._aad_from_container(container))
        del file_key

        # 2) ADD nonce, ciphertext and tag
        container["nonce"] = _b64e(nonce)
        container["ciphertext"] = _b64e(sealed[:-TAG_SIZE])
        container["tag"] = _b64e(sealed[-TAG_SIZE:])

        # 3) SIGN everything above
        container["signature"] = _b64e(signer_private_key.sign(self._signed_digest(container)))

        # 4) STORE as JSON
        return json.dumps(container, sort_keys=True, indent=2).encode("utf-8")

    # =======================================================================
    # Parsing and verification (ALWAYS before decrypting)
    # =======================================================================
    @staticmethod
    def parse_container(container_bytes) -> dict:
        """
        Parses the container and validates its STRUCTURE. It does NOT verify the signature:
        never trust the result of this function alone (use verify_container).
        """
        if not isinstance(container_bytes, (bytes, bytearray)):
            raise ContainerFormatError("Invalid container: expected bytes.")
        try:
            container = json.loads(bytes(container_bytes).decode("utf-8"),
                                   object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise ContainerFormatError("Invalid container: not valid JSON.") from None
        if not isinstance(container, dict):
            raise ContainerFormatError("Invalid container: wrong structure.")

        missing = REQUIRED_FIELDS - container.keys()
        if "signature" in missing or not container.get("signature"):
            raise SignatureError("Signature rejected: the container is not signed.")
        if missing:
            raise ContainerFormatError(f"Invalid container: missing fields {sorted(missing)}.")
        extra = container.keys() - REQUIRED_FIELDS
        if extra:
            raise ContainerFormatError(f"Invalid container: unauthenticated fields {sorted(extra)}.")
        if container["format"] != CONTAINER_FORMAT or container["version"] != CONTAINER_VERSION \
                or isinstance(container["version"], bool):
            raise ContainerFormatError("Invalid container: unsupported format or version.")

        meta = container["metadata"]
        if not isinstance(meta, dict) or set(meta) != REQUIRED_METADATA:
            raise ContainerFormatError("Invalid container: malformed metadata.")
        if (meta["algorithm"] != FILE_ALGORITHM or meta["key_wrap"] != KEY_WRAP_ALGORITHM
                or meta["signature_algorithm"] != SIGNATURE_ALGORITHM):
            raise ContainerFormatError("Invalid container: unsupported algorithm.")
        if not isinstance(meta["filename"], str) or not isinstance(meta["timestamp"], int) \
                or isinstance(meta["timestamp"], bool):
            raise ContainerFormatError("Invalid container: malformed metadata.")

        recipients = container["recipients"]
        if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
            raise ContainerFormatError("Invalid container: malformed recipient list.")
        for r in recipients:
            if not isinstance(r, dict) or set(r) != REQUIRED_RECIPIENT_FIELDS \
                    or not all(isinstance(r[f], str) for f in REQUIRED_RECIPIENT_FIELDS):
                raise ContainerFormatError("Invalid container: malformed recipient entry.")
        if not isinstance(container["signer_id"], str):
            raise ContainerFormatError("Invalid container: malformed signer_id.")
        return container

    def verify_container(self, container_bytes, sender_public_key) -> dict:
        """
        1. Parse and validate the structure  2. Check the expected signer  3. Verify the Ed25519 signature.
        Returns the container (dict) only if the signature is valid.
        """
        if not isinstance(sender_public_key, Ed25519PublicKey):
            raise SignatureError("The sender's trusted Ed25519 public key is required.")
        container = self.parse_container(container_bytes)

        # The declared signer must be the key we trust for this sender
        if container["signer_id"] != self.key_fingerprint(sender_public_key):
            raise SignatureError("Signature rejected: the signer does not match the trusted public key.")

        signature = _b64d(container["signature"], SIGNATURE_SIZE, "signature")
        try:
            sender_public_key.verify(signature, self._signed_digest(container))
        except InvalidSignature:
            raise SignatureError(
                "Signature rejected: the file or its metadata were modified, or the signature is forged.") from None
        return container

    def decrypt_file(self, container_bytes, my_private_key, my_key_id: str = None,
                     sender_public_key=None) -> bytes:
        """
        Verify signature -> find MY entry by the fingerprint of MY key -> unwrap DEK -> decrypt.
        my_key_id (optional): if given, it must match the label or fingerprint of my entry.
        No plaintext is ever returned unless every check succeeds.
        """
        # 1. Signature FIRST (nothing cryptographic is done with unauthenticated data)
        container = self.verify_container(container_bytes, sender_public_key)

        # 2. Validate every field that will be used, before using any of them
        nonce = _b64d(container["nonce"], NONCE_SIZE, "nonce")
        ciphertext = _b64d(container["ciphertext"], None, "ciphertext")
        tag = _b64d(container["tag"], TAG_SIZE, "tag")

        # 3. My entry is found by the fingerprint of MY key, not by a self-declared name
        if not _is_p256_private(my_private_key):
            raise AccessDeniedError("Access denied: a P-256 private key is required.")
        my_fingerprint = self.key_fingerprint(my_private_key.public_key())
        entry = next((r for r in container["recipients"] if r["key_id"] == my_fingerprint), None)
        if entry is None or (my_key_id is not None and my_key_id not in (entry["id"], entry["key_id"])):
            raise AccessDeniedError("Access denied: this key is not in the recipient list.")

        # 4. Unwrap the file key (KEK != DEK) and decrypt the file
        file_key = self._ecies_decrypt_key(my_private_key, entry["encrypted_key"], my_fingerprint)
        if len(file_key) != FILE_KEY_SIZE:
            raise IntegrityError("Integrity error: invalid file key.")
        try:
            return AESGCM(file_key).decrypt(nonce, ciphertext + tag, self._aad_from_container(container))
        except InvalidTag:
            raise IntegrityError(
                "Integrity error: the file, its metadata or the recipient list were modified.") from None
