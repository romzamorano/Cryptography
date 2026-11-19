"""
Exception hierarchy of the Secure Digital Document Vault.

Every error raised on purpose by the vault is a VaultError. VaultError inherits from
ValueError, so code (and tests) that already catch ValueError keep working.

Messages are short and never include internal exception details (they are raised
"from None"), so a failure does not reveal WHICH internal check failed beyond what
the user needs to know.
"""


class VaultError(ValueError):
    """Base class of every error raised by the vault."""


# --------------------------------------------------------------------------- containers
class ContainerFormatError(VaultError):
    """The container (or one of its fields) is malformed, truncated or unsupported."""


class SignatureError(VaultError):
    """The signature is missing, invalid, or does not belong to the expected sender."""


class AccessDeniedError(VaultError):
    """The given private key is not one of the recipients of the container."""


class IntegrityError(VaultError):
    """Authenticated decryption failed (AES-GCM tag did not verify)."""


class RecipientError(VaultError):
    """The recipient list given to encrypt_file is invalid (empty, duplicated, wrong key...)."""


# --------------------------------------------------------------------------- keystore (D6)
class KeystoreError(VaultError):
    """Base class of keystore errors."""


class KeystoreFormatError(KeystoreError):
    """The keystore file is malformed, corrupted or uses unsupported parameters."""


class KeystoreAuthError(KeystoreError):
    """Wrong password or tampered keystore (AES-GCM authentication failed)."""


class KeystoreNotFoundError(KeystoreError):
    """The keystore file does not exist or cannot be read."""


class KeystoreExistsError(KeystoreError):
    """Refusing to overwrite an existing keystore file."""


class WeakPasswordError(KeystoreError):
    """The password does not meet the password policy."""


class KeyRevokedError(KeystoreError):
    """The key was marked as compromised and can never be used again."""


class KeyInactiveError(KeystoreError):
    """The key is retired (rotated) or expired."""
