"""
Trust store - which public keys a user trusts, and for whom (D5 + D6 feedback).

A fingerprint IDENTIFIES a key, but it does not prove who owns it. Trust is established
when a user imports a contact's public keys and compares the fingerprints with the
contact through an independent channel (in person, by phone...), like Signal safety
numbers or SSH host keys. From then on:

  * Encrypting for "Bob" uses the encryption key trusted for Bob (and its fingerprint).
  * A file "from Alice" is only accepted if it is signed by a signing key trusted for Alice.
  * If a contact's key changes, the change is refused unless explicitly accepted
    (protection against key substitution).
  * Revoked keys (compromised) are refused forever: files signed with them are rejected
    and no new files are encrypted for them.
  * Keys replaced by a rotation become 'retired': they still verify OLD files, but new
    files are always encrypted for the active key.

Public keys are exchanged as a "public key bundle" (JSON) exported by each user.
"""
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vault.crypto_module import SecureEncryptionModule
from vault.errors import (ContactKeyRevokedError, ContactNotFoundError, KeyChangedError,
                          SignatureError, TrustStoreError)
from vault.keystore import _atomic_write_private

TRUST_STORE_FORMAT = "SDDV-TRUSTSTORE"
TRUST_STORE_VERSION = 1
BUNDLE_FORMAT = "SDDV-PUBLIC-KEYS"
BUNDLE_VERSION = 1
MAX_FILE_SIZE = 1024 * 1024
MAX_NAME_LENGTH = 64

KEY_ACTIVE = "active"
KEY_RETIRED = "retired"
KEY_REVOKED = "revoked"
KEY_STATUSES = {KEY_ACTIVE, KEY_RETIRED, KEY_REVOKED}
KEY_KINDS = ("encryption", "signing")

fingerprint = SecureEncryptionModule.key_fingerprint


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pem(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _load_pem(text, kind: str):
    """Loads a PEM public key and checks it is the right type for its purpose."""
    if not isinstance(text, str):
        raise TrustStoreError(f"Invalid {kind} public key.")
    try:
        key = serialization.load_pem_public_key(text.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        raise TrustStoreError(f"Invalid {kind} public key.") from None
    if kind == "encryption" and not (isinstance(key, ec.EllipticCurvePublicKey)
                                     and isinstance(key.curve, ec.SECP256R1)):
        raise TrustStoreError("The encryption key must be a P-256 public key.")
    if kind == "signing" and not isinstance(key, Ed25519PublicKey):
        raise TrustStoreError("The signing key must be an Ed25519 public key.")
    return key


def validate_name(name) -> str:
    """User / contact names: letters, digits, '-', '_' and '.' (they are also folder names)."""
    if not isinstance(name, str) or not 1 <= len(name) <= MAX_NAME_LENGTH \
            or not all(c.isalnum() or c in "-_." for c in name) or name.startswith("."):
        raise TrustStoreError("Invalid name: use 1-64 letters, digits, '-', '_' or '.'.")
    return name


# ---------------------------------------------------------------------------
# Public key bundles (what a user gives to their contacts)
# ---------------------------------------------------------------------------
def export_public_bundle(name: str, encryption_public_key, signing_public_key) -> bytes:
    """Public keys of a user + their fingerprints, to be shared with contacts."""
    validate_name(name)
    bundle = {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "name": name,
        "encryption_key": _pem(encryption_public_key),
        "encryption_fingerprint": fingerprint(encryption_public_key),
        "signing_key": _pem(signing_public_key),
        "signing_fingerprint": fingerprint(signing_public_key),
    }
    return json.dumps(bundle, indent=2).encode("utf-8")


def load_public_bundle(data: bytes) -> dict:
    """
    Parses a bundle and checks it is internally consistent (the listed fingerprints match
    the keys). This detects corruption, NOT impersonation: anybody can create a bundle with
    any name. The user must still compare the fingerprints with the real owner.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE_SIZE:
        raise TrustStoreError("Invalid public key bundle.")
    try:
        bundle = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise TrustStoreError("Invalid public key bundle: not valid JSON.") from None
    expected = {"format", "version", "name", "encryption_key", "encryption_fingerprint",
                "signing_key", "signing_fingerprint"}
    if not isinstance(bundle, dict) or set(bundle) != expected:
        raise TrustStoreError("Invalid public key bundle: unexpected or missing fields.")
    if bundle["format"] != BUNDLE_FORMAT or bundle["version"] != BUNDLE_VERSION:
        raise TrustStoreError("Invalid public key bundle: unsupported format or version.")
    name = validate_name(bundle["name"])
    enc = _load_pem(bundle["encryption_key"], "encryption")
    sign = _load_pem(bundle["signing_key"], "signing")
    if fingerprint(enc) != bundle["encryption_fingerprint"] or fingerprint(sign) != bundle["signing_fingerprint"]:
        raise TrustStoreError("Invalid public key bundle: fingerprints do not match the keys.")
    return {"name": name, "encryption_key": enc, "signing_key": sign,
            "encryption_fingerprint": fingerprint(enc), "signing_fingerprint": fingerprint(sign)}


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------
class TrustStore:
    """
    JSON file:
    {"format": "SDDV-TRUSTSTORE", "version": 1, "contacts": {
        "Alice": {"added_at": "...",
                  "encryption": [{"fingerprint": "p256:...", "public_key": "PEM", "status": "active",
                                  "added_at": "...", "changed_at": null}],
                  "signing":    [{"fingerprint": "ed25519:...", ...}]}}}
    The file is stored in the user's local (trusted) environment with 0600 permissions.
    """

    def __init__(self, path: str):
        self.path = path
        self.contacts = {}
        if os.path.exists(path):
            self._load()

    # ---------------------------------------------------------------- storage
    def _load(self):
        try:
            with open(self.path, "rb") as f:
                raw = f.read(MAX_FILE_SIZE + 1)
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise TrustStoreError(f"The trust store could not be read: {self.path}") from None
        if len(raw) > MAX_FILE_SIZE or not isinstance(data, dict) \
                or data.get("format") != TRUST_STORE_FORMAT or data.get("version") != TRUST_STORE_VERSION \
                or not isinstance(data.get("contacts"), dict):
            raise TrustStoreError("Invalid trust store file.")
        for name, contact in data["contacts"].items():
            validate_name(name)
            if not isinstance(contact, dict):
                raise TrustStoreError("Invalid trust store file.")
            for kind in KEY_KINDS:
                entries = contact.get(kind)
                if not isinstance(entries, list) or not entries:
                    raise TrustStoreError("Invalid trust store file.")
                for e in entries:
                    if not isinstance(e, dict) or e.get("status") not in KEY_STATUSES:
                        raise TrustStoreError("Invalid trust store file.")
                    if fingerprint(_load_pem(e.get("public_key"), kind)) != e.get("fingerprint"):
                        raise TrustStoreError("Invalid trust store file: fingerprint mismatch.")
        self.contacts = data["contacts"]

    def save(self):
        data = {"format": TRUST_STORE_FORMAT, "version": TRUST_STORE_VERSION, "contacts": self.contacts}
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        _atomic_write_private(self.path, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))

    # ---------------------------------------------------------------- queries
    def _contact(self, name: str) -> dict:
        if name not in self.contacts:
            raise ContactNotFoundError(f"Unknown contact: {name}. Import their public keys first.")
        return self.contacts[name]

    def names(self):
        return sorted(self.contacts)

    def entries(self, name: str, kind: str):
        return list(self._contact(name)[kind])

    def _active(self, name: str, kind: str) -> dict:
        entry = next((e for e in self._contact(name)[kind] if e["status"] == KEY_ACTIVE), None)
        if entry is None:
            raise ContactKeyRevokedError(f"{name} has no active {kind} key (it was revoked).")
        return entry

    def encryption_recipient(self, name: str) -> dict:
        """Recipient entry for encrypt_file: the ACTIVE trusted key + its expected fingerprint."""
        entry = self._active(name, "encryption")
        return {"id": name, "public_key": _load_pem(entry["public_key"], "encryption"),
                "fingerprint": entry["fingerprint"]}

    def active_signing_key(self, name: str):
        return _load_pem(self._active(name, "signing")["public_key"], "signing")

    def signing_key_for(self, name: str, signer_id: str):
        """
        Trusted signing key of `name` whose fingerprint is `signer_id` (the value declared in
        the container). Active and retired keys are accepted (retired = rotated, still valid
        for files signed before the rotation); revoked keys are refused.
        """
        for e in self._contact(name)["signing"]:
            if e["fingerprint"] == signer_id:
                if e["status"] == KEY_REVOKED:
                    raise ContactKeyRevokedError(
                        f"The file is signed with a REVOKED key of {name} ({signer_id[:24]}...).")
                return _load_pem(e["public_key"], "signing")
        raise SignatureError(f"Signature rejected: the file is not signed by any trusted key of {name}.")

    def is_revoked(self, key_fingerprint: str) -> bool:
        return any(e["fingerprint"] == key_fingerprint and e["status"] == KEY_REVOKED
                   for c in self.contacts.values() for kind in KEY_KINDS for e in c[kind])

    # ---------------------------------------------------------------- changes
    def add_contact(self, name: str, encryption_public_key, signing_public_key,
                    expected_encryption_fp: str = None, expected_signing_fp: str = None,
                    accept_key_change: bool = False) -> str:
        """
        Adds (or updates) a contact. Returns "added", "unchanged" or "updated".
        * expected_*_fp: fingerprints confirmed with the owner out of band. If given, they must match.
        * If the contact exists with DIFFERENT keys, the change is refused (KeyChangedError) unless
          accept_key_change=True; then the old active keys become 'retired'.
        * A revoked key can never be trusted again.
        """
        validate_name(name)
        keys = {"encryption": (_load_pem(_pem(encryption_public_key), "encryption"), expected_encryption_fp),
                "signing": (_load_pem(_pem(signing_public_key), "signing"), expected_signing_fp)}
        for kind, (key, expected) in keys.items():
            if expected is not None and fingerprint(key) != expected:
                raise TrustStoreError(f"The {kind} key of {name} does not match the expected fingerprint.")
            if self.is_revoked(fingerprint(key)):
                raise ContactKeyRevokedError(f"The {kind} key {fingerprint(key)[:24]}... was revoked.")

        now = _now_iso()
        if name not in self.contacts:
            self.contacts[name] = {"added_at": now, **{
                kind: [{"fingerprint": fingerprint(key), "public_key": _pem(key), "status": KEY_ACTIVE,
                        "added_at": now, "changed_at": None}] for kind, (key, _) in keys.items()}}
            self.save()
            return "added"

        contact = self.contacts[name]
        changed = [kind for kind, (key, _) in keys.items()
                   if not any(e["fingerprint"] == fingerprint(key) and e["status"] == KEY_ACTIVE
                              for e in contact[kind])]
        if not changed:
            return "unchanged"
        if not accept_key_change:
            raise KeyChangedError(
                f"The {' and '.join(changed)} key of {name} CHANGED. This can be a legitimate rotation "
                "or a key-substitution attack: confirm the new fingerprint with the owner first.")
        for kind in changed:
            key = keys[kind][0]
            for e in contact[kind]:
                if e["status"] == KEY_ACTIVE:
                    e["status"], e["changed_at"] = KEY_RETIRED, now
            previous = next((e for e in contact[kind] if e["fingerprint"] == fingerprint(key)), None)
            if previous is not None:            # re-activating a retired key
                previous["status"], previous["changed_at"] = KEY_ACTIVE, now
            else:
                contact[kind].append({"fingerprint": fingerprint(key), "public_key": _pem(key),
                                      "status": KEY_ACTIVE, "added_at": now, "changed_at": None})
        self.save()
        return "updated"

    def import_bundle(self, data: bytes, expected_encryption_fp: str = None, expected_signing_fp: str = None,
                      accept_key_change: bool = False, name: str = None) -> str:
        bundle = load_public_bundle(data)
        return self.add_contact(name or bundle["name"], bundle["encryption_key"], bundle["signing_key"],
                                expected_encryption_fp, expected_signing_fp, accept_key_change)

    def revoke(self, name: str, kind: str = "all", key_fingerprint: str = None) -> int:
        """
        Marks a contact's key(s) as REVOKED (e.g. the contact reported a stolen laptop).
        kind: "encryption", "signing" or "all". If key_fingerprint is given, only that key.
        Returns how many keys were revoked.
        """
        contact = self._contact(name)
        kinds = KEY_KINDS if kind == "all" else (kind,)
        if any(k not in KEY_KINDS for k in kinds):
            raise TrustStoreError(f"Unknown key kind: {kind}")
        count, now = 0, _now_iso()
        for k in kinds:
            for e in contact[k]:
                if e["status"] != KEY_REVOKED and (key_fingerprint is None or e["fingerprint"] == key_fingerprint):
                    e["status"], e["changed_at"] = KEY_REVOKED, now
                    count += 1
        if count:
            self.save()
        return count
