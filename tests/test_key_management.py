import os
import json
import base64
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from vault.keystore import SecureKeyStore, public_key_fingerprint
from vault.crypto_module import SecureEncryptionModule

# Fast KDF ONLY for the tests (production default and minimum: 600,000 iterations)
TEST_ITERATIONS = 1000


def _flip_last_b64_char(value: str) -> str:
    """Flips one bit of the decoded bytes (the result is still valid Base64)."""
    raw = bytearray(base64.b64decode(value))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class TestKeyManagement(unittest.TestCase):
    """The 5 tests required by D6."""

    def setUp(self):
        self.keystore = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=TEST_ITERATIONS)

        # Temporary directory to avoid cluttering the repository with test files
        self.test_dir = tempfile.mkdtemp()
        self.key_path = os.path.join(self.test_dir, "test_keystore.json")
        self.backup_dir = os.path.join(self.test_dir, "backup")

        self.password = "SuperSecretPassword123!"
        self.wrong_password = "WrongPassword456!"
        self.key_id = "Alice_P256"
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def assertSameKey(self, a, b):
        self.assertEqual(a.private_numbers().private_value, b.private_numbers().private_value)

    def test_1_correct_password_access_granted(self):
        """Correct password -> access granted"""
        recovered_key = self.keystore.load_and_decrypt_key(self.key_path, self.password)
        self.assertSameKey(self.private_key, recovered_key)

    def test_2_wrong_password_access_denied(self):
        """Wrong password -> access denied"""
        with self.assertRaises(ValueError) as context:
            self.keystore.load_and_decrypt_key(self.key_path, self.wrong_password)
        self.assertIn("Incorrect password or tampered Keystore", str(context.exception))

    def test_3_modified_keystore_failure(self):
        """Modified keystore -> failure (ciphertext, tag, nonce, salt and metadata)"""
        with open(self.key_path) as f:
            original = json.load(f)

        tamperings = {
            "ciphertext": lambda d: d.update(encrypted_private_key=_flip_last_b64_char(d["encrypted_private_key"])),
            "tag": lambda d: d.update(tag=_flip_last_b64_char(d["tag"])),
            "nonce": lambda d: d.update(nonce=_flip_last_b64_char(d["nonce"])),
            "salt": lambda d: d["kdf_parameters"].update(salt=_flip_last_b64_char(d["kdf_parameters"]["salt"])),
            "key_id": lambda d: d["metadata"].update(key_id="Eve_P256"),
            "key_type": lambda d: d["metadata"].update(key_type="Ed25519"),
            "status": lambda d: d["metadata"].update(status="retired"),
            "expires_at": lambda d: d["metadata"].update(expires_at="2099-01-01T00:00:00Z"),
            "iterations": lambda d: d["kdf_parameters"].update(iterations=TEST_ITERATIONS + 1),
            "extra_field": lambda d: d.update(note="hello"),
        }
        for name, tamper in tamperings.items():
            with self.subTest(tampered=name):
                data = json.loads(json.dumps(original))
                tamper(data)
                with open(self.key_path, "w") as f:
                    json.dump(data, f)
                with self.assertRaises(ValueError):
                    self.keystore.load_and_decrypt_key(self.key_path, self.password)

    def test_4_backup_restore_works(self):
        """Backup -> restore works"""
        backup_path = self.keystore.backup_keystore(self.key_path, self.backup_dir)
        self.assertTrue(os.path.exists(backup_path))

        # The original is lost (disk failure, formatted computer...)
        os.remove(self.key_path)

        # Restore the keystore from the backup with the password
        meta = self.keystore.restore_keystore(backup_path, self.password, self.key_path)
        self.assertEqual(meta["key_id"], self.key_id)
        recovered_key = self.keystore.load_and_decrypt_key(self.key_path, self.password)
        self.assertSameKey(self.private_key, recovered_key)

    def test_5_stolen_keystore_alone_cannot_decrypt(self):
        """Stolen keystore alone -> cannot decrypt (neither the key nor Alice's files)"""
        # Alice receives a signed, encrypted file (D3 + D5)
        vault = SecureEncryptionModule()
        sign_priv, sign_pub = SecureEncryptionModule.generate_signing_keypair()
        container = vault.encrypt_file(
            b"top secret", [{"id": "Alice", "public_key": self.private_key.public_key()}],
            filename="secret.txt", signer_private_key=sign_priv)

        # The attacker copies the keystore file: it contains NO plaintext private key
        with open(self.key_path, "rb") as f:
            stolen = f.read()
        raw_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        raw_der = self.private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.assertNotIn(b"PRIVATE KEY", stolen)
        self.assertNotIn(raw_pem, stolen)
        self.assertNotIn(raw_der, stolen)

        # Guessing passwords fails (offline dictionary attack)
        for guess in ["password", "123456", "admin", "Alice123", "SuperSecretPassword123"]:
            with self.assertRaises(ValueError):
                self.keystore.load_and_decrypt_key(self.key_path, guess)

        # Without the real private key, the file cannot be opened
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(ValueError):
            vault.decrypt_file(container, attacker_key, "Alice", sign_pub)

        # Only Alice (keystore + password) can decrypt it
        with self.keystore.unlocked_key(self.key_path, self.password) as alice_key:
            self.assertEqual(vault.decrypt_file(container, alice_key, "Alice", sign_pub), b"top secret")


class TestKeyLifecycle(unittest.TestCase):
    """Extra D6 tests: KDF policy, key identity, password prompt, lifecycle and recovery."""

    def setUp(self):
        self.keystore = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=TEST_ITERATIONS)
        self.test_dir = tempfile.mkdtemp()
        self.path = os.path.join(self.test_dir, "alice_p256.json")
        self.password = "correct horse battery staple"
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", self.path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_kdf_downgrade_rejected(self):
        """A keystore asking for fewer iterations than the minimum is refused."""
        strict = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=600_000)
        with self.assertRaises(ValueError) as ctx:
            strict.load_and_decrypt_key(self.path, self.password)
        self.assertIn("iterations", str(ctx.exception))

    def test_default_kdf_parameters(self):
        ks = SecureKeyStore()
        self.assertEqual(ks.iterations, 600_000)
        self.assertEqual(ks.min_iterations, 600_000)
        with open(self.path) as f:
            data = json.load(f)
        self.assertEqual(data["kdf_parameters"]["algorithm"], "PBKDF2HMAC-SHA256")
        self.assertEqual(data["metadata"]["encryption"], "AES-256-GCM")

    def test_weak_password_rejected_on_creation(self):
        with self.assertRaises(ValueError):
            self.keystore.encrypt_and_save_key(self.key, "123456", "Alice", "P-256",
                                               os.path.join(self.test_dir, "weak.json"))

    def test_unique_salt_and_nonce(self):
        """Same key + same password -> different salt, nonce and ciphertext."""
        other = os.path.join(self.test_dir, "copy.json")
        self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", other)
        with open(self.path) as f1, open(other) as f2:
            a, b = json.load(f1), json.load(f2)
        self.assertNotEqual(a["kdf_parameters"]["salt"], b["kdf_parameters"]["salt"])
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["encrypted_private_key"], b["encrypted_private_key"])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_keystore_file_permissions(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_password_is_prompted_and_not_stored(self):
        """Without a password argument the key is unlocked via getpass; the password is not saved."""
        with mock.patch("vault.keystore.getpass.getpass", return_value=self.password) as prompt:
            with self.keystore.unlocked_key(self.path) as priv:
                self.assertEqual(priv.private_numbers().private_value,
                                 self.key.private_numbers().private_value)
            prompt.assert_called_once()
        with open(self.path, "rb") as f:
            self.assertNotIn(self.password.encode(), f.read())

    def test_key_identity_consistent(self):
        """Fingerprint and public key in the metadata identify the key without the password."""
        meta = self.keystore.read_metadata(self.path)
        self.assertEqual(meta["public_key_fingerprint"], public_key_fingerprint(self.key.public_key()))
        self.assertEqual(public_key_fingerprint(self.keystore.load_public_key(self.path)),
                         meta["public_key_fingerprint"])
        self.assertEqual(meta["purpose"], "encryption")

    def test_ed25519_fingerprint_matches_d5_signer_id(self):
        sign_priv, sign_pub = SecureEncryptionModule.generate_signing_keypair()
        path = os.path.join(self.test_dir, "alice_ed25519.json")
        self.keystore.encrypt_and_save_key(sign_priv, self.password, "Alice-sign", "Ed25519", path)
        self.assertEqual(self.keystore.read_metadata(path)["public_key_fingerprint"],
                         SecureEncryptionModule.key_fingerprint(sign_pub))
        self.assertEqual(self.keystore.read_metadata(path)["purpose"], "signing")

    def test_key_type_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "Ed25519",
                                               os.path.join(self.test_dir, "bad.json"))

    def test_swapped_private_key_rejected(self):
        """Pasting Bob's encrypted key into Alice's keystore (same password) fails."""
        bob_path = os.path.join(self.test_dir, "bob.json")
        self.keystore.encrypt_and_save_key(ec.generate_private_key(ec.SECP256R1()), self.password,
                                           "Bob", "P-256", bob_path)
        with open(self.path) as f1, open(bob_path) as f2:
            alice, bob = json.load(f1), json.load(f2)
        for field in ("nonce", "encrypted_private_key", "tag"):
            alice[field] = bob[field]
        alice["kdf_parameters"]["salt"] = bob["kdf_parameters"]["salt"]
        with open(self.path, "w") as f:
            json.dump(alice, f)
        with self.assertRaises(ValueError):
            self.keystore.load_and_decrypt_key(self.path, self.password)

    def test_change_password(self):
        new_password = "a brand new long passphrase"
        self.keystore.change_password(self.path, self.password, new_password)
        with self.assertRaises(ValueError):
            self.keystore.load_and_decrypt_key(self.path, self.password)
        recovered = self.keystore.load_and_decrypt_key(self.path, new_password)
        self.assertEqual(recovered.private_numbers().private_value, self.key.private_numbers().private_value)

    def test_key_rotation(self):
        """New key is active; old key is retired but can still open OLD files."""
        vault = SecureEncryptionModule()
        sign_priv, sign_pub = SecureEncryptionModule.generate_signing_keypair()
        old_file = vault.encrypt_file(b"old file", [{"id": "Alice", "public_key": self.key.public_key()}],
                                      signer_private_key=sign_priv)

        new_path = os.path.join(self.test_dir, "alice_p256_v2.json")
        new_pub = self.keystore.rotate_key(self.path, self.password, new_path, "Alice-v2")

        self.assertNotEqual(public_key_fingerprint(new_pub), public_key_fingerprint(self.key.public_key()))
        self.assertEqual(self.keystore.read_metadata(self.path)["status"], "retired")
        self.assertEqual(self.keystore.read_metadata(new_path)["status"], "active")

        with self.assertRaises(ValueError):
            self.keystore.load_and_decrypt_key(self.path, self.password)
        old_key = self.keystore.load_and_decrypt_key(self.path, self.password, allow_inactive=True)
        self.assertEqual(vault.decrypt_file(old_file, old_key, "Alice", sign_pub), b"old file")

        new_key = self.keystore.load_and_decrypt_key(new_path, self.password)
        new_file = vault.encrypt_file(b"new file", [{"id": "Alice-v2", "public_key": new_pub}],
                                      signer_private_key=sign_priv)
        self.assertEqual(vault.decrypt_file(new_file, new_key, "Alice-v2", sign_pub), b"new file")

    def test_compromised_key_refused(self):
        self.keystore.mark_compromised(self.path, self.password)
        for allow in (False, True):
            with self.assertRaises(ValueError) as ctx:
                self.keystore.load_and_decrypt_key(self.path, self.password, allow_inactive=allow)
            self.assertIn("compromised", str(ctx.exception))

    def test_expired_key(self):
        path = os.path.join(self.test_dir, "expired.json")
        past = datetime.now(timezone.utc) - timedelta(days=1)
        self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", path, expires_at=past)
        with self.assertRaises(ValueError) as ctx:
            self.keystore.load_and_decrypt_key(path, self.password)
        self.assertIn("expired", str(ctx.exception))
        self.assertIsNotNone(self.keystore.load_and_decrypt_key(path, self.password, allow_inactive=True))

        future = datetime.now(timezone.utc) + timedelta(days=365)
        self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", path, expires_at=future)
        self.assertIsNotNone(self.keystore.load_and_decrypt_key(path, self.password))

    def test_restore_verifies_backup(self):
        """Wrong password or tampered backup -> nothing is restored."""
        backup = self.keystore.backup_keystore(self.path, os.path.join(self.test_dir, "usb"))
        dest = os.path.join(self.test_dir, "restored.json")

        with self.assertRaises(ValueError):
            self.keystore.restore_keystore(backup, "not the password!!", dest)
        self.assertFalse(os.path.exists(dest))

        with open(backup) as f:
            data = json.load(f)
        data["metadata"]["key_id"] = "Mallory"
        with open(backup, "w") as f:
            json.dump(data, f)
        with self.assertRaises(ValueError):
            self.keystore.restore_keystore(backup, self.password, dest)
        self.assertFalse(os.path.exists(dest))

    def test_restore_does_not_overwrite_by_default(self):
        backup = self.keystore.backup_keystore(self.path, os.path.join(self.test_dir, "usb"))
        with self.assertRaises(ValueError):
            self.keystore.restore_keystore(backup, self.password, self.path)
        self.keystore.restore_keystore(backup, self.password, self.path, overwrite=True)


if __name__ == '__main__':
    unittest.main()
