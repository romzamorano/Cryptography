"""
D6 - Secure Key Management

Password-protected keystore for the private keys of the Secure Digital Document Vault:
  * P-256 private keys  -> used to unwrap file keys (ECIES, D3)
  * Ed25519 private keys -> used to sign containers (D5)

Private keys are NEVER written to disk in plaintext. Each key lives in its own JSON
keystore file, encrypted with AES-256-GCM under a key derived from the user's password
with PBKDF2-HMAC-SHA256. The whole header (format, version, metadata and KDF parameters)
is authenticated as AAD, so any modification of the keystore makes unlocking fail.

See D6-Key_Management.md for the full design.
"""
import os
import json
import base64
import getpass
import binascii
import hashlib
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidTag

from vault.errors import (KeyInactiveError, KeyRevokedError, KeystoreAuthError, KeystoreError,
                          KeystoreExistsError, KeystoreFormatError, KeystoreNotFoundError,
                          WeakPasswordError)

# ---------------------------------------------------------------------------
# Keystore format constants
# ---------------------------------------------------------------------------
KEYSTORE_FORMAT = "SDDV-KEYSTORE"
KEYSTORE_VERSION = 1
KDF_ALGORITHM = "PBKDF2HMAC-SHA256"
ENCRYPTION_ALGORITHM = "AES-256-GCM"

DEFAULT_ITERATIONS = 600_000   # OWASP (2023+) recommendation for PBKDF2-HMAC-SHA256
MIN_ITERATIONS = 600_000       # a keystore asking for fewer iterations is rejected (downgrade)
MAX_ITERATIONS = 10_000_000    # a keystore asking for more is rejected (denial of service)
MAX_KEYSTORE_SIZE = 64 * 1024  # bytes; a real keystore is ~1.5 KB
MAX_PASSWORD_LENGTH = 1024
KEY_LENGTH = 32                # 256-bit AES key
SALT_SIZE = 16                 # 128-bit random salt per keystore
NONCE_SIZE = 12                # 96-bit AES-GCM nonce
TAG_SIZE = 16                  # 128-bit AES-GCM tag
MIN_PASSWORD_LENGTH = 12       # password policy enforced when a keystore is created
# Small list of very common passwords that satisfy the length rule (rejected explicitly)
COMMON_PASSWORDS = {
    "password1234", "password12345", "password123!", "passwordpassword", "123456789012",
    "1234567890123", "qwertyuiop12", "qwerty123456", "iloveyou1234", "contraseña123",
    "contrasena123", "contrasena1234", "administrator", "letmein12345", "welcome12345",
}

KEY_TYPES = {
    "P-256": "encryption",     # ECIES (D3): unwrap file keys
    "Ed25519": "signing",      # Ed25519 (D5): sign containers
}
STATUS_ACTIVE = "active"            # normal use
STATUS_RETIRED = "retired"          # replaced by rotation: only to open OLD files
STATUS_COMPROMISED = "compromised"  # revoked: never usable again
STATUSES = {STATUS_ACTIVE, STATUS_RETIRED, STATUS_COMPROMISED}

REQUIRED_FIELDS = {
    "format", "version", "metadata", "kdf_parameters",
    "nonce", "encrypted_private_key", "tag",
}
REQUIRED_METADATA = {
    "key_id", "key_type", "purpose", "encryption", "public_key",
    "public_key_fingerprint", "created_at", "expires_at", "status",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text, expected_len=None, field=""):
    if not isinstance(text, str):
        raise KeystoreFormatError(f"Invalid keystore: field '{field}' is not Base64.")
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise KeystoreFormatError(f"Invalid keystore: field '{field}' is not valid Base64.") from None
    if expected_len is not None and len(data) != expected_len:
        raise KeystoreFormatError(f"Invalid keystore: wrong length in '{field}'.")
    return data


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _reject_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise KeystoreFormatError("Invalid keystore: duplicated JSON keys.")
    return dict(pairs)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _atomic_write_private(filepath: str, data: bytes, overwrite: bool = True):
    """
    Writes the file atomically and with owner-only permissions (0600 on POSIX).
    With overwrite=False an existing file is never replaced: the final step is a hard
    link, which fails atomically if the destination already exists.
    On Windows, os.chmod only toggles the read-only flag: access there is controlled by
    the user profile's ACLs (keep the keystore folder inside the user's home).
    """
    directory = os.path.dirname(os.path.abspath(filepath))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".keystore-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        if overwrite:
            os.replace(tmp, filepath)
        else:
            try:
                os.link(tmp, filepath)          # atomic "create only if it does not exist"
            except FileExistsError:
                raise KeystoreExistsError(
                    f"Refusing to overwrite existing file: {filepath} (use overwrite=True).") from None
            except OSError:
                # File systems without hard links (e.g. FAT USB drives): best-effort check
                if os.path.exists(filepath):
                    raise KeystoreExistsError(
                        f"Refusing to overwrite existing file: {filepath} (use overwrite=True).") from None
                os.replace(tmp, filepath)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def public_key_fingerprint(public_key) -> str:
    """
    Stable identity of a key = SHA-256 of its public key.
      * Ed25519 -> "ed25519:<hex>"  (same value as SecureEncryptionModule.key_fingerprint / signer_id in D5)
      * P-256   -> "p256:<hex>"     (SHA-256 of the uncompressed X9.62 point)
    """
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return "ed25519:" + hashlib.sha256(raw).hexdigest()
    if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1):
        raw = public_key.public_bytes(serialization.Encoding.X962,
                                      serialization.PublicFormat.UncompressedPoint)
        return "p256:" + hashlib.sha256(raw).hexdigest()
    raise KeystoreError("Unsupported key: only P-256 and Ed25519 keys are allowed.")


def _key_type_of(private_key) -> str:
    if isinstance(private_key, Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP256R1):
        return "P-256"
    raise KeystoreError("Unsupported key: only P-256 and Ed25519 keys are allowed.")


def _generate_key(key_type: str):
    if key_type == "P-256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "Ed25519":
        return Ed25519PrivateKey.generate()
    raise KeystoreError(f"Unsupported key type: {key_type}")


def prompt_password(prompt: str = "Keystore password: ", confirm: bool = False) -> str:
    """Asks for the password without echoing it. The password is never stored."""
    password = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat password: ") != password:
        raise WeakPasswordError("Passwords do not match.")
    return password


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------
class SecureKeyStore:
    def __init__(self, iterations: int = DEFAULT_ITERATIONS, min_iterations: int = MIN_ITERATIONS,
                 min_password_length: int = MIN_PASSWORD_LENGTH, max_iterations: int = MAX_ITERATIONS):
        # KDF parameters aligned with current security standards
        self.kdf_algorithm = KDF_ALGORITHM
        self.iterations = iterations                  # used when CREATING a keystore
        self.min_iterations = min_iterations          # lowest value accepted when OPENING one
        self.max_iterations = max_iterations          # highest value accepted (DoS protection)
        self.key_length = KEY_LENGTH                  # 256 bits for AES-GCM
        self.min_password_length = min_password_length

    # ------------------------------------------------------------------ KDF
    def _derive_key(self, password: str, salt: bytes, iterations: int = None) -> bytes:
        """Derives a 256-bit symmetric key from the password (PBKDF2-HMAC-SHA256)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=iterations if iterations is not None else self.iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def _check_password_policy(self, password: str):
        """
        Password policy (applied when a keystore is created or its password is changed).
        The keystore can be stolen and attacked OFFLINE, so the password is the real
        security boundary: length matters most, and trivially guessable values are refused.
        """
        if not isinstance(password, str) or len(password) < self.min_password_length:
            raise WeakPasswordError(
                f"Weak password: use at least {self.min_password_length} characters "
                "(a long passphrase is recommended).")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise WeakPasswordError(f"Password too long (maximum {MAX_PASSWORD_LENGTH} characters).")
        lowered = password.lower()
        if lowered in COMMON_PASSWORDS:
            raise WeakPasswordError("Weak password: it is in the list of most common passwords.")
        if len(set(password)) < 5:
            raise WeakPasswordError("Weak password: it repeats too few different characters.")
        if password.isdigit():
            raise WeakPasswordError("Weak password: use words or mixed characters, not only digits.")
        steps = {ord(b) - ord(a) for a, b in zip(password, password[1:])}
        if steps <= {1} or steps <= {-1}:
            raise WeakPasswordError("Weak password: simple sequences (abcd..., 1234...) are not allowed.")

    @staticmethod
    def _aad(keystore: dict) -> bytes:
        """AAD = everything except the ciphertext: format, version, metadata and KDF parameters."""
        return _canonical_json({
            "format": keystore["format"],
            "version": keystore["version"],
            "metadata": keystore["metadata"],
            "kdf_parameters": keystore["kdf_parameters"],
        })

    # --------------------------------------------------------------- create
    def _build_keystore(self, private_key, password: str, metadata: dict) -> dict:
        raw_priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        keystore = {
            "format": KEYSTORE_FORMAT,
            "version": KEYSTORE_VERSION,
            "metadata": metadata,
            "kdf_parameters": {
                "algorithm": self.kdf_algorithm,
                "iterations": self.iterations,
                "key_length": self.key_length,
                "salt": _b64e(salt),
            },
        }
        derived_key = self._derive_key(password, salt, self.iterations)
        encrypted = AESGCM(derived_key).encrypt(nonce, raw_priv_bytes, self._aad(keystore))
        keystore["nonce"] = _b64e(nonce)
        keystore["encrypted_private_key"] = _b64e(encrypted[:-TAG_SIZE])
        keystore["tag"] = _b64e(encrypted[-TAG_SIZE:])
        return keystore

    def encrypt_and_save_key(self, private_key, password: str, key_id: str, key_type: str,
                             filepath: str, expires_at: datetime = None, status: str = STATUS_ACTIVE,
                             created_at: str = None, overwrite: bool = False):
        """
        Encrypts a private key and saves it in a structured keystore file (JSON).
        key_type must be "P-256" (ECIES, D3) or "Ed25519" (signatures, D5).
        expires_at (optional) is a timezone-aware datetime after which the key is no longer active.
        An existing keystore is NEVER overwritten unless overwrite=True (losing a private key
        means losing access to every file encrypted for it).
        """
        self._check_password_policy(password)
        if key_type not in KEY_TYPES:
            raise KeystoreError(f"Unsupported key type: {key_type}")
        if _key_type_of(private_key) != key_type:
            raise KeystoreError("Key identity mismatch: key_type does not match the private key.")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise KeystoreError("key_id must be a non-empty string (max 128 characters).")
        if status not in STATUSES:
            raise KeystoreError(f"Invalid status: {status}")
        if not overwrite and os.path.exists(filepath):
            raise KeystoreExistsError(f"Keystore already exists: {filepath} (use overwrite=True).")

        public_key = private_key.public_key()
        metadata = {
            "key_id": key_id,
            "key_type": key_type,
            "purpose": KEY_TYPES[key_type],
            "encryption": ENCRYPTION_ALGORITHM,
            "public_key": public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
            "public_key_fingerprint": public_key_fingerprint(public_key),
            "created_at": created_at or _iso(_now_utc()),
            "expires_at": _iso(expires_at) if expires_at is not None else None,
            "status": status,
        }
        keystore = self._build_keystore(private_key, password, metadata)
        _atomic_write_private(filepath, json.dumps(keystore, indent=4).encode("utf-8"), overwrite=overwrite)
        return keystore

    # ----------------------------------------------------------------- read
    def _read_keystore(self, filepath: str) -> dict:
        """Parses and validates the STRUCTURE (not the authenticity) of a keystore file."""
        if os.path.isdir(filepath):
            # Checked first: on Windows, opening a directory raises PermissionError
            raise KeystoreNotFoundError(f"Keystore path is a directory: {filepath}")
        try:
            with open(filepath, "rb") as f:
                raw = f.read(MAX_KEYSTORE_SIZE + 1)
        except FileNotFoundError:
            raise KeystoreNotFoundError(f"Keystore not found: {filepath}") from None
        except IsADirectoryError:
            raise KeystoreNotFoundError(f"Keystore path is a directory: {filepath}") from None
        except PermissionError:
            raise KeystoreError(f"Permission denied reading the keystore: {filepath}") from None
        except OSError:
            raise KeystoreError(f"The keystore could not be read: {filepath}") from None
        if len(raw) > MAX_KEYSTORE_SIZE:
            raise KeystoreFormatError("Invalid keystore: file too large.")
        try:
            keystore = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise KeystoreFormatError("Invalid keystore: not valid JSON.") from None
        if not isinstance(keystore, dict) or set(keystore) != REQUIRED_FIELDS:
            raise KeystoreFormatError("Invalid keystore: unexpected or missing fields.")
        if keystore["format"] != KEYSTORE_FORMAT or keystore["version"] != KEYSTORE_VERSION \
                or isinstance(keystore["version"], bool):
            raise KeystoreFormatError("Invalid keystore: unknown format or version.")
        meta = keystore["metadata"]
        if not isinstance(meta, dict) or set(meta) != REQUIRED_METADATA:
            raise KeystoreFormatError("Invalid keystore: malformed metadata.")
        self._validate_metadata(meta)
        kdf = keystore["kdf_parameters"]
        if not isinstance(kdf, dict) or set(kdf) != {"algorithm", "iterations", "key_length", "salt"}:
            raise KeystoreFormatError("Invalid keystore: malformed KDF parameters.")
        if kdf["algorithm"] != KDF_ALGORITHM or kdf["key_length"] != KEY_LENGTH:
            raise KeystoreFormatError("Invalid keystore: unsupported KDF.")
        # Downgrade and DoS protection: checked BEFORE deriving (the AAD check happens later)
        if not isinstance(kdf["iterations"], int) or isinstance(kdf["iterations"], bool) \
                or kdf["iterations"] < self.min_iterations:
            raise KeystoreFormatError("Invalid keystore: KDF iterations below the allowed minimum.")
        if kdf["iterations"] > self.max_iterations:
            raise KeystoreFormatError("Invalid keystore: KDF iterations above the allowed maximum.")
        return keystore

    @staticmethod
    def _validate_metadata(meta: dict):
        """Types and values of the (not yet authenticated) metadata, so nothing crashes later."""
        if meta["key_type"] not in KEY_TYPES or meta["purpose"] != KEY_TYPES[meta["key_type"]]:
            raise KeystoreFormatError("Invalid keystore: unknown key type.")
        if meta["status"] not in STATUSES or meta["encryption"] != ENCRYPTION_ALGORITHM:
            raise KeystoreFormatError("Invalid keystore: malformed metadata.")
        for field in ("key_id", "public_key", "public_key_fingerprint", "created_at"):
            if not isinstance(meta[field], str) or not meta[field]:
                raise KeystoreFormatError(f"Invalid keystore: malformed '{field}'.")
        for field in ("created_at", "expires_at"):
            value = meta[field]
            if value is None and field == "expires_at":
                continue
            try:
                if not isinstance(value, str):
                    raise ValueError
                _parse_iso(value)
            except ValueError:
                raise KeystoreFormatError(f"Invalid keystore: malformed '{field}'.") from None

    def read_metadata(self, filepath: str) -> dict:
        """
        Public information of the keystore (key_id, type, public key, fingerprint, status...).
        Does NOT need the password. Note: it is only authenticated when the key is unlocked.
        """
        return dict(self._read_keystore(filepath)["metadata"])

    def load_public_key(self, filepath: str):
        return serialization.load_pem_public_key(
            self.read_metadata(filepath)["public_key"].encode("ascii"))

    def _unlock(self, filepath: str, password: str):
        """Returns (private_key, keystore) after full authentication. No lifecycle checks."""
        keystore = self._read_keystore(filepath)
        kdf = keystore["kdf_parameters"]
        salt = _b64d(kdf["salt"], SALT_SIZE, "salt")
        nonce = _b64d(keystore["nonce"], NONCE_SIZE, "nonce")
        ciphertext = _b64d(keystore["encrypted_private_key"], None, "encrypted_private_key")
        tag = _b64d(keystore["tag"], TAG_SIZE, "tag")

        # Derive the key with the parameters stored in the keystore (they are authenticated as AAD)
        if not isinstance(password, str):
            raise KeystoreAuthError("Incorrect password or tampered Keystore (Integrity failure).")
        derived_key = self._derive_key(password, salt, kdf["iterations"])
        try:
            raw_priv_bytes = AESGCM(derived_key).decrypt(nonce, ciphertext + tag, self._aad(keystore))
        except InvalidTag:
            raise KeystoreAuthError("Incorrect password or tampered Keystore (Integrity failure).") from None

        try:
            private_key = serialization.load_pem_private_key(raw_priv_bytes, password=None)
        except (ValueError, TypeError):
            raise KeystoreFormatError("Invalid keystore: the decrypted private key is malformed.") from None
        finally:
            del raw_priv_bytes

        # Key identity consistency: the decrypted key must match the declared type and fingerprint
        meta = keystore["metadata"]
        if (_key_type_of(private_key) != meta["key_type"] or
                public_key_fingerprint(private_key.public_key()) != meta["public_key_fingerprint"]):
            raise KeystoreFormatError("Key identity mismatch: keystore metadata does not match the private key.")
        return private_key, keystore

    def load_and_decrypt_key(self, filepath: str, password: str, allow_inactive: bool = False):
        """
        Reads the keystore, derives the key with the provided password and decrypts the private key.
        Lifecycle rules (D6):
          * compromised        -> always refused
          * retired / expired  -> refused unless allow_inactive=True (only to open OLD files)
        """
        private_key, keystore = self._unlock(filepath, password)
        meta = keystore["metadata"]
        if meta["status"] == STATUS_COMPROMISED:
            raise KeyRevokedError("Key revoked: this key was marked as compromised and cannot be used.")
        if not allow_inactive:
            if meta["status"] == STATUS_RETIRED:
                raise KeyInactiveError("Key retired: it was rotated. Use allow_inactive=True only to open old files.")
            if meta["expires_at"] is not None and _now_utc() >= _parse_iso(meta["expires_at"]):
                raise KeyInactiveError("Key expired: rotate it to keep using the system.")
        return private_key

    @contextmanager
    def unlocked_key(self, filepath: str, password: str = None, allow_inactive: bool = False):
        """
        Decrypts the private key ONLY for the duration of the `with` block.
        If no password is given, it is requested with getpass (not echoed, never stored).

            with keystore.unlocked_key("keys/alice_p256.json") as priv:
                vault.decrypt_file(container, priv, "Alice", alice_sign_pub)
        """
        if password is None:
            password = prompt_password(f"Password for {os.path.basename(filepath)}: ")
        private_key = self.load_and_decrypt_key(filepath, password, allow_inactive)
        del password
        try:
            yield private_key
        finally:
            # Drop the reference so the key is not cached after use (see limitations in D6 doc)
            del private_key

    # ------------------------------------------------------------ lifecycle
    def _rewrite(self, filepath: str, private_key, password: str, metadata: dict):
        keystore = self._build_keystore(private_key, password, metadata)
        _atomic_write_private(filepath, json.dumps(keystore, indent=4).encode("utf-8"))
        return keystore

    def change_password(self, filepath: str, old_password: str, new_password: str):
        """Re-encrypts the same private key with a new password (new salt and nonce)."""
        self._check_password_policy(new_password)
        private_key, keystore = self._unlock(filepath, old_password)
        return self._rewrite(filepath, private_key, new_password, keystore["metadata"])

    def rotate_key(self, old_filepath: str, password: str, new_filepath: str, new_key_id: str,
                   expires_at: datetime = None):
        """
        Key rotation: generates a NEW key of the same type, stores it as 'active', and marks the
        old keystore as 'retired' (it can still open old files with allow_inactive=True).
        Returns the new public key, which must be distributed to the other users.
        """
        if os.path.abspath(old_filepath) == os.path.abspath(new_filepath):
            raise KeystoreError("The new keystore must be a different file.")
        old_key, old_keystore = self._unlock(old_filepath, password)
        old_meta = dict(old_keystore["metadata"])
        if old_meta["status"] == STATUS_COMPROMISED:
            raise KeyRevokedError("Key revoked: generate a fresh key instead of rotating a compromised one.")

        new_key = _generate_key(old_meta["key_type"])
        self.encrypt_and_save_key(new_key, password, new_key_id, old_meta["key_type"],
                                  new_filepath, expires_at=expires_at)
        old_meta["status"] = STATUS_RETIRED
        self._rewrite(old_filepath, old_key, password, old_meta)
        return new_key.public_key()

    def mark_compromised(self, filepath: str, password: str):
        """Compromise response: revokes the key so the system refuses to use it again."""
        private_key, keystore = self._unlock(filepath, password)
        meta = dict(keystore["metadata"])
        meta["status"] = STATUS_COMPROMISED
        return self._rewrite(filepath, private_key, password, meta)

    # ------------------------------------------------------ backup/recovery
    def backup_keystore(self, filepath: str, backup_dir: str) -> str:
        """
        Copies the ENCRYPTED keystore to backup_dir (e.g. a USB drive). The password is not needed
        and the private key is never decrypted. Returns the path of the backup file.
        """
        meta = self.read_metadata(filepath)   # validates structure before copying
        stamp = _now_utc().strftime("%Y%m%dT%H%M%SZ")
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in meta["key_id"])
        with open(filepath, "rb") as f:
            data = f.read()
        # Never overwrite an older backup (two backups in the same second get a counter)
        for n in range(1000):
            suffix = "" if n == 0 else f"_{n}"
            backup_path = os.path.join(backup_dir, f"{safe_id}_{stamp}{suffix}.keystore.json")
            try:
                _atomic_write_private(backup_path, data, overwrite=False)
                break
            except KeystoreExistsError:
                continue
        else:
            raise KeystoreError("Too many backups with the same timestamp.")
        # Verify the copy (detects a faulty destination drive)
        with open(backup_path, "rb") as f:
            if hashlib.sha256(f.read()).digest() != hashlib.sha256(data).digest():
                raise KeystoreError("Backup verification failed: the copy differs from the original.")
        return backup_path

    def restore_keystore(self, backup_path: str, password: str, dest_filepath: str,
                         overwrite: bool = False, expected_fingerprint: str = None) -> dict:
        """
        Restores a keystore from a backup. The backup is VERIFIED first (correct password, intact
        file, consistent key identity and, if given, the EXPECTED key fingerprint, e.g. the one
        the user's contacts know); only then is it copied to dest_filepath.
        """
        if os.path.exists(dest_filepath) and not overwrite:
            raise KeystoreExistsError("Destination keystore already exists (use overwrite=True).")
        _, keystore = self._unlock(backup_path, password)
        meta = keystore["metadata"]
        if expected_fingerprint is not None and meta["public_key_fingerprint"] != expected_fingerprint:
            raise KeystoreError("Backup rejected: it contains a different key than the expected one "
                                f"({meta['public_key_fingerprint'][:21]}...).")
        with open(backup_path, "rb") as f:
            _atomic_write_private(dest_filepath, f.read(), overwrite=overwrite)
        return dict(meta)
