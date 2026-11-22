"""
Application layer of the Secure Digital Document Vault.

It connects every module in the way a real user works, and it is what the interactive
CLI (vault/cli.py) calls. Keeping this logic here (and not in the menu) makes every use
case testable automatically (tests/integration/test_app_flow.py).

Folder layout (all inside `home`, default ./vault_home):

    vault_home/
    ├── shared/                      <- UNTRUSTED channel / storage: .vault packages are left here
    ├── public/<name>.pub.json       <- published public-key bundles (also untrusted)
    └── users/<name>/                <- each user's LOCAL, trusted environment
        ├── keys/encryption.json     <- active P-256 keystore (encrypted, D6)
        ├── keys/signing.json        <- active Ed25519 keystore (encrypted, D6)
        ├── keys/retired/            <- keystores replaced by a rotation (open old files)
        ├── contacts.json            <- trust store
        ├── replay_cache.json        <- packages already received
        └── inbox/                   <- decrypted files
"""
import os
import re
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec

from vault.crypto_module import SecureEncryptionModule
from vault.errors import (AccessDeniedError, KeystoreError, KeystoreExistsError,
                          TrustStoreError, VaultError)
from vault.keystore import DEFAULT_ITERATIONS, MIN_ITERATIONS, SecureKeyStore
from vault.replay_guard import ReplayGuard
from vault.trust_store import TrustStore, export_public_bundle, load_public_bundle, validate_name

KEY_KINDS = {"encryption": "P-256", "signing": "Ed25519"}
MAX_INPUT_FILE_SIZE = 100 * 1024 * 1024        # 100 MiB: whole files are encrypted in memory


def sanitize_filename(name) -> str:
    """
    Turns an UNTRUSTED file name (it comes from a package) into a safe plain file name:
    no folders ('../../x' -> 'x'), no leading dots (hidden files), no control or
    reserved characters, limited length.
    """
    if not isinstance(name, str):
        name = ""
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r'[\x00-\x1f\x7f<>:"|?*]', "_", name).strip().lstrip(".").strip()
    if name.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                                      *(f"LPT{i}" for i in range(1, 10))}:
        name = "_" + name
    return name[:120] or "received_file"


def unique_path(folder: str, name: str) -> str:
    """Never overwrite: 'report.txt' -> 'report (1).txt' if it already exists."""
    base, ext = os.path.splitext(name)
    candidate, n = os.path.join(folder, name), 1
    while os.path.exists(candidate):
        candidate = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return candidate


def _write_new_file(path: str, data: bytes):
    """Creates the file exclusively (fails instead of overwriting)."""
    with open(path, "xb") as f:
        f.write(data)


class Step:
    """One verification step, reported to the user while a file is sent or received."""

    def __init__(self, number: int, total: int, ok: bool, text: str):
        self.number, self.total, self.ok, self.text = number, total, ok, text


class VaultApp:
    def __init__(self, home: str = "vault_home", iterations: int = DEFAULT_ITERATIONS,
                 min_iterations: int = MIN_ITERATIONS, clock=time.time):
        self.home = os.path.abspath(home)
        self.keystore = SecureKeyStore(iterations=iterations, min_iterations=min_iterations)
        self.vault = SecureEncryptionModule()
        self.clock = clock
        for folder in (self.shared_dir, self.public_dir, self.users_dir):
            os.makedirs(folder, exist_ok=True)

    # ------------------------------------------------------------------ paths
    @property
    def shared_dir(self):
        return os.path.join(self.home, "shared")

    @property
    def public_dir(self):
        return os.path.join(self.home, "public")

    @property
    def users_dir(self):
        return os.path.join(self.home, "users")

    def user_dir(self, name: str) -> str:
        return os.path.join(self.users_dir, validate_name(name))

    def key_path(self, name: str, kind: str) -> str:
        if kind not in KEY_KINDS:
            raise VaultError(f"Unknown key kind: {kind}")
        return os.path.join(self.user_dir(name), "keys", f"{kind}.json")

    def retired_dir(self, name: str) -> str:
        return os.path.join(self.user_dir(name), "keys", "retired")

    def inbox_dir(self, name: str) -> str:
        return os.path.join(self.user_dir(name), "inbox")

    def trust(self, name: str) -> TrustStore:
        return TrustStore(os.path.join(self.user_dir(name), "contacts.json"))

    def replay_guard(self, name: str) -> ReplayGuard:
        return ReplayGuard(os.path.join(self.user_dir(name), "replay_cache.json"), clock=self.clock)

    def bundle_path(self, name: str) -> str:
        return os.path.join(self.public_dir, f"{validate_name(name)}.pub.json")

    # ------------------------------------------------------------------ users
    def list_users(self):
        return sorted(n for n in os.listdir(self.users_dir)
                      if os.path.exists(os.path.join(self.users_dir, n, "keys", "encryption.json")))

    def _require_user(self, name: str):
        if name not in self.list_users():
            raise VaultError(f"Unknown user: {name}")

    def create_user(self, name: str, password: str) -> dict:
        """Generates the P-256 (encryption) and Ed25519 (signing) key pairs, stores them ENCRYPTED,
        publishes the public-key bundle and trusts the user's own keys."""
        validate_name(name)
        if os.path.exists(self.user_dir(name)):
            raise KeystoreExistsError(f"The user {name} already exists.")
        self.keystore._check_password_policy(password)          # before creating anything
        enc_priv = ec.generate_private_key(ec.SECP256R1())
        sign_priv, _ = SecureEncryptionModule.generate_signing_keypair()
        self.keystore.encrypt_and_save_key(enc_priv, password, name, "P-256", self.key_path(name, "encryption"))
        self.keystore.encrypt_and_save_key(sign_priv, password, f"{name}-sign", "Ed25519",
                                           self.key_path(name, "signing"))
        del enc_priv, sign_priv
        os.makedirs(self.inbox_dir(name), exist_ok=True)
        self.trust(name).add_contact(name, self.public_key(name, "encryption"), self.public_key(name, "signing"))
        self.publish_bundle(name)
        return self.fingerprints(name)

    def public_key(self, name: str, kind: str):
        return self.keystore.load_public_key(self.key_path(name, kind))

    def fingerprints(self, name: str) -> dict:
        return {kind: self.keystore.read_metadata(self.key_path(name, kind))["public_key_fingerprint"]
                for kind in KEY_KINDS}

    def key_report(self, name: str) -> list:
        """Every keystore of the user (active and retired) with its public metadata."""
        self._require_user(name)
        rows = []
        for kind in KEY_KINDS:
            rows.append(dict(self.keystore.read_metadata(self.key_path(name, kind)), file=f"{kind}.json"))
        if os.path.isdir(self.retired_dir(name)):
            for f in sorted(os.listdir(self.retired_dir(name))):
                rows.append(dict(self.keystore.read_metadata(os.path.join(self.retired_dir(name), f)),
                                 file=f"retired/{f}"))
        return rows

    def publish_bundle(self, name: str) -> str:
        data = export_public_bundle(name, self.public_key(name, "encryption"), self.public_key(name, "signing"))
        path = self.bundle_path(name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def change_password(self, name: str, kind: str, old_password: str, new_password: str):
        self.keystore.change_password(self.key_path(name, kind), old_password, new_password)

    def rotate_key(self, name: str, kind: str, password: str) -> str:
        """New key pair of the same kind; the old keystore is moved to keys/retired/ and keeps
        opening OLD files. The new public key is re-published (contacts must re-import it)."""
        active = self.key_path(name, kind)
        os.makedirs(self.retired_dir(name), exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        new_tmp = os.path.join(self.user_dir(name), "keys", f".{kind}.new.json")
        label = name if kind == "encryption" else f"{name}-sign"
        self.keystore.rotate_key(active, password, new_tmp, f"{label}-{stamp}")
        os.replace(active, unique_path(self.retired_dir(name), f"{kind}_{stamp}.json"))
        os.replace(new_tmp, active)
        self.trust(name).add_contact(name, self.public_key(name, "encryption"), self.public_key(name, "signing"),
                                     accept_key_change=True)
        self.publish_bundle(name)
        return self.fingerprints(name)[kind]

    def mark_compromised(self, name: str, kind: str, password: str):
        """The key can never be used again. Contacts must be told to revoke it."""
        fp = self.fingerprints(name)[kind]
        self.keystore.mark_compromised(self.key_path(name, kind), password)
        self.trust(name).revoke(name, kind, fp)
        return fp

    def replace_compromised_key(self, name: str, kind: str, password: str) -> str:
        """After a compromise: a brand-new key pair replaces the revoked one (which is kept,
        revoked, in keys/retired/ only as a record). The new public key is re-published."""
        active = self.key_path(name, kind)
        if self.keystore.read_metadata(active)["status"] != "compromised":
            raise KeystoreError("This key is not compromised: use rotation instead.")
        self.keystore._check_password_policy(password)
        new_key = ec.generate_private_key(ec.SECP256R1()) if kind == "encryption" \
            else SecureEncryptionModule.generate_signing_keypair()[0]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        os.makedirs(self.retired_dir(name), exist_ok=True)
        new_tmp = os.path.join(self.user_dir(name), "keys", f".{kind}.new.json")
        label = name if kind == "encryption" else f"{name}-sign"
        self.keystore.encrypt_and_save_key(new_key, password, f"{label}-{stamp}", KEY_KINDS[kind], new_tmp)
        del new_key
        os.replace(active, unique_path(self.retired_dir(name), f"{kind}_{stamp}_compromised.json"))
        os.replace(new_tmp, active)
        self.trust(name).add_contact(name, self.public_key(name, "encryption"), self.public_key(name, "signing"),
                                     accept_key_change=True)
        self.publish_bundle(name)
        return self.fingerprints(name)[kind]

    def backup(self, name: str, destination: str) -> list:
        return [self.keystore.backup_keystore(self.key_path(name, kind), destination) for kind in KEY_KINDS]

    def restore(self, name: str, kind: str, backup_path: str, password: str, overwrite: bool = False) -> dict:
        """Restores a keystore, checking it holds the key this user is KNOWN for (own trust store)."""
        expected = None
        try:
            expected = next(e["fingerprint"] for e in self.trust(name).entries(name, kind) if e["status"] == "active")
        except (TrustStoreError, StopIteration):
            pass
        return self.keystore.restore_keystore(backup_path, password, self.key_path(name, kind),
                                              overwrite=overwrite, expected_fingerprint=expected)

    # --------------------------------------------------------------- contacts
    def list_bundles(self):
        return sorted(f for f in os.listdir(self.public_dir) if f.endswith(".pub.json"))

    def preview_bundle(self, path: str) -> dict:
        with open(path, "rb") as f:
            return load_public_bundle(f.read())

    def import_contact(self, user: str, bundle_file: str, expected_encryption_fp: str = None,
                       expected_signing_fp: str = None, accept_key_change: bool = False) -> str:
        self._require_user(user)
        with open(bundle_file, "rb") as f:
            data = f.read()
        return self.trust(user).import_bundle(data, expected_encryption_fp or None, expected_signing_fp or None,
                                              accept_key_change)

    def contacts(self, user: str) -> list:
        store = self.trust(user)
        return [{"name": n, "encryption": store.entries(n, "encryption"), "signing": store.entries(n, "signing")}
                for n in store.names()]

    def revoke_contact(self, user: str, contact: str, kind: str = "all") -> int:
        return self.trust(user).revoke(contact, kind)

    # ------------------------------------------------------------------ files
    def list_shared(self):
        return sorted(f for f in os.listdir(self.shared_dir) if f.endswith(".vault"))

    def shared_path(self, name: str) -> str:
        return os.path.join(self.shared_dir, sanitize_filename(name))

    def send_file(self, sender: str, password: str, file_path: str, recipients: list,
                  include_self: bool = True, progress=None, timestamp: int = None, filename: str = None) -> str:
        """Encrypt once -> wrap the file key for every TRUSTED recipient -> sign -> leave it in shared/."""
        report = progress or (lambda step: None)
        self._require_user(sender)
        if not os.path.isfile(file_path):
            raise VaultError(f"File not found: {file_path}")
        if os.path.getsize(file_path) > MAX_INPUT_FILE_SIZE:
            raise VaultError("File too large (maximum 100 MiB).")
        names = list(dict.fromkeys(([sender] if include_self else []) + list(recipients)))
        if not names:
            raise VaultError("Choose at least one recipient.")
        store = self.trust(sender)
        resolved = [store.encryption_recipient(n) for n in names]
        report(Step(1, 4, True, "Recipients resolved from your TRUSTED contacts: "
                    + ", ".join(f"{r['id']} ({r['fingerprint'][:17]}...)" for r in resolved)))
        with open(file_path, "rb") as f:
            plaintext = f.read()
        with self.keystore.unlocked_key(self.key_path(sender, "signing"), password) as sign_key:
            report(Step(2, 4, True, "Signing key unlocked from your keystore (PBKDF2-HMAC-SHA256 + AES-256-GCM)"))
            data = self.vault.encrypt_file(plaintext, resolved, filename or os.path.basename(file_path),
                                           signer_private_key=sign_key, timestamp=timestamp)
        report(Step(3, 4, True, f"File encrypted ONCE with a fresh AES-256-GCM file key; the file key was "
                                f"wrapped for {len(resolved)} recipient(s) with ECIES (ECDH P-256 + HKDF + AES-GCM)"))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out = unique_path(self.shared_dir, f"{sanitize_filename(os.path.basename(file_path))}.{sender}.{stamp}.vault")
        _write_new_file(out, data)
        report(Step(4, 4, True, f"Package signed with Ed25519 and stored in the shared folder: {os.path.basename(out)}"))
        return out

    def inspect(self, vault_path: str) -> dict:
        """Header of a package WITHOUT verifying it (what anybody with access to the storage sees)."""
        with open(vault_path, "rb") as f:
            return self.vault.parse_container(f.read())

    def receive_file(self, user: str, password: str, vault_path: str, expected_sender: str,
                     allow_reopen: bool = False, progress=None) -> str:
        """
        1 parse -> 2 trusted signer -> 3 signature -> 4 freshness/replay -> 5 my key is a recipient
        -> 6 unwrap + decrypt -> save in the inbox (never overwriting). Nothing is written unless
        every step succeeds. Each step is reported through `progress`.
        """
        report = progress or (lambda step: None)
        total = 6
        self._require_user(user)
        step = 1
        try:
            with open(vault_path, "rb") as f:
                data = f.read()
            container = self.vault.parse_container(data)
            report(Step(1, total, True, f"Package structure valid ({container['format']} v{container['version']}, "
                                        f"{len(container['recipients'])} recipient(s))"))
            step = 2
            sender_key = self.trust(user).signing_key_for(expected_sender, container["signer_id"])
            report(Step(2, total, True, f"Declared signer {container['signer_id'][:24]}... is a TRUSTED key "
                                        f"of {expected_sender}"))
            step = 3
            container = self.vault.verify_container(data, sender_key)
            report(Step(3, total, True, "Ed25519 signature valid: nothing was modified since it was signed"))
            step = 4
            guard = self.replay_guard(user)
            age = int(self.clock() - container["metadata"]["timestamp"])
            if allow_reopen and guard.received_before(container):
                report(Step(4, total, True, "Package received before: re-opening it (explicitly allowed)"))
            else:
                guard.check(container)
                report(Step(4, total, True, f"Fresh package (signed {max(age, 0) // 60} min ago) "
                                            "and never received before"))
            step = 5
            mine = self._my_matching_key(user, container)
            report(Step(5, total, True, f"Your key {mine[1][:24]}... is in the recipient list"
                                        + (" (retired key)" if "retired" in mine[0] else "")))
            step = 6
            with self.keystore.unlocked_key(mine[0], password, allow_inactive=True) as enc_key:
                plaintext = self.vault.decrypt_file(data, enc_key, None, sender_key)
        except (VaultError, OSError) as e:
            report(Step(step, total, False, str(e) if isinstance(e, VaultError) else f"File error: {e.strerror}"))
            raise
        out = unique_path(self.inbox_dir(user), sanitize_filename(container["metadata"]["filename"]))
        os.makedirs(self.inbox_dir(user), exist_ok=True)
        _write_new_file(out, plaintext)
        if not guard.received_before(container):
            guard.record(container)
        report(Step(6, total, True, "File key unwrapped (ECDH + HKDF + AES-GCM) and file decrypted and "
                                    f"authenticated (AES-256-GCM) -> inbox/{os.path.basename(out)}"))
        return out

    def _my_matching_key(self, user: str, container: dict):
        """Which of MY keystores (active or retired) is a recipient, found by fingerprint, no password needed."""
        listed = {r["key_id"] for r in container["recipients"]}
        candidates = [self.key_path(user, "encryption")]
        if os.path.isdir(self.retired_dir(user)):
            candidates += [os.path.join(self.retired_dir(user), f) for f in sorted(os.listdir(self.retired_dir(user)))
                           if f.startswith("encryption")]
        for path in candidates:
            try:
                fp = self.keystore.read_metadata(path)["public_key_fingerprint"]
            except KeystoreError:
                continue
            if fp in listed:
                return path, fp
        raise AccessDeniedError("Access denied: none of your keys is in the recipient list.")

