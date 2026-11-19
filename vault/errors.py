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
