"""
Keystore hardening (feedback D6):

  * Existing keystores are never overwritten by accident.
  * KDF parameters are bounded (minimum against downgrade, maximum against denial of service).
  * Malformed JSON, invalid Base64, corrupted KDF parameters, missing fields and file errors
    are rejected with specific exceptions.
  * Password policy rejects trivially guessable passwords.
  * Backups never overwrite each other and restore verifies the expected key identity.
"""
import base64
import json
import os
import shutil
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from vault.errors import (KeystoreAuthError, KeystoreError, KeystoreExistsError, KeystoreFormatError,
                          KeystoreNotFoundError, VaultError, WeakPasswordError)
from vault.keystore import MAX_ITERATIONS, SecureKeyStore, public_key_fingerprint

TEST_ITERATIONS = 1000


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keystore = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=TEST_ITERATIONS)
        self.password = "a long and private passphrase"
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.path = os.path.join(self.dir, "alice.json")
        self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", self.path)
        with open(self.path, "rb") as f:
            self.pristine = f.read()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def load_json(self):
        """Always starts from the original, untouched keystore."""
        self.write_raw(self.pristine)
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def save_json(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def write_raw(self, raw: bytes):
        with open(self.path, "wb") as f:
            f.write(raw)

    def unlock(self):
        return self.keystore.load_and_decrypt_key(self.path, self.password)


class TestNoAccidentalOverwrite(_Base):

    def test_creating_over_existing_keystore_is_refused(self):
        original = open(self.path, "rb").read()
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(KeystoreExistsError):
            self.keystore.encrypt_and_save_key(other, self.password, "Alice", "P-256", self.path)
        self.assertEqual(open(self.path, "rb").read(), original)       # untouched
        self.assertEqual(self.unlock().private_numbers().private_value, self.key.private_numbers().private_value)

    def test_explicit_overwrite_is_allowed(self):
        other = ec.generate_private_key(ec.SECP256R1())
        self.keystore.encrypt_and_save_key(other, self.password, "Alice", "P-256", self.path, overwrite=True)
        self.assertEqual(self.unlock().private_numbers().private_value, other.private_numbers().private_value)

    def test_rotation_never_overwrites_an_existing_new_keystore(self):
        existing = os.path.join(self.dir, "bob.json")
        self.keystore.encrypt_and_save_key(ec.generate_private_key(ec.SECP256R1()), self.password,
                                           "Bob", "P-256", existing)
        with self.assertRaises(KeystoreExistsError):
            self.keystore.rotate_key(self.path, self.password, existing, "Alice-v2")
        self.assertEqual(self.keystore.read_metadata(self.path)["status"], "active")   # old key not retired

    def test_no_temporary_files_left_behind(self):
        with self.assertRaises(KeystoreExistsError):
            self.keystore.encrypt_and_save_key(self.key, self.password, "Alice", "P-256", self.path)
        self.assertEqual(os.listdir(self.dir), ["alice.json"])


class TestKdfParameterBounds(_Base):

    def test_huge_iteration_count_rejected_before_deriving(self):
        """An attacker sets 10^12 iterations: rejected immediately instead of hanging the app."""
        data = self.load_json()
        data["kdf_parameters"]["iterations"] = 10 ** 12
        self.save_json(data)
        start = time.monotonic()
        with self.assertRaises(KeystoreFormatError):
            self.unlock()
        self.assertLess(time.monotonic() - start, 1.0)

    def test_iterations_at_maximum_are_accepted_by_the_parser(self):
        ks = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=TEST_ITERATIONS)
        self.assertEqual(ks.max_iterations, MAX_ITERATIONS)

    def test_corrupted_kdf_parameters_rejected(self):
        edits = {
            "iterations_string": lambda k: k.update(iterations="600000"),
            "iterations_bool": lambda k: k.update(iterations=True),
            "iterations_negative": lambda k: k.update(iterations=-1),
            "algorithm": lambda k: k.update(algorithm="MD5"),
            "key_length": lambda k: k.update(key_length=16),
            "salt_not_base64": lambda k: k.update(salt="%%%"),
            "salt_short": lambda k: k.update(salt=base64.b64encode(b"short").decode()),
            "missing_salt": lambda k: k.pop("salt"),
            "extra_field": lambda k: k.update(memory_cost=1),
        }
        for name, edit in edits.items():
            with self.subTest(case=name):
                data = self.load_json()
                edit(data["kdf_parameters"])
                self.save_json(data)
                with self.assertRaises(KeystoreFormatError):
                    self.unlock()


class TestMalformedKeystores(_Base):

    def test_malformed_files_rejected(self):
        cases = {
            "empty": b"",
            "not_json": b"this is not json",
            "binary": os.urandom(200),
            "not_utf8": b"\xff\xfe{}",
            "json_list": b"[]",
            "truncated": open(self.path, "rb").read()[:100],
            "too_large": b" " * (70 * 1024),
            "duplicated_keys": b'{"format": 1, "format": 2}',
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                self.write_raw(raw)
                with self.assertRaises(KeystoreFormatError):
                    self.unlock()

    def test_missing_or_wrongly_typed_fields_rejected(self):
        edits = {
            "missing_nonce": lambda d: d.pop("nonce"),
            "missing_metadata": lambda d: d.pop("metadata"),
            "nonce_not_base64": lambda d: d.update(nonce="***"),
            "tag_wrong_length": lambda d: d.update(tag=base64.b64encode(b"x").decode()),
            "ciphertext_not_string": lambda d: d.update(encrypted_private_key=123),
            "version": lambda d: d.update(version=2),
            "status_unknown": lambda d: d["metadata"].update(status="hacked"),
            "key_type_unknown": lambda d: d["metadata"].update(key_type="RSA"),
            "created_at_garbage": lambda d: d["metadata"].update(created_at="yesterday"),
            "expires_at_number": lambda d: d["metadata"].update(expires_at=12345),
            "key_id_empty": lambda d: d["metadata"].update(key_id=""),
        }
        for name, edit in edits.items():
            with self.subTest(case=name):
                data = self.load_json()
                edit(data)
                self.save_json(data)
                with self.assertRaises(KeystoreFormatError):
                    self.unlock()

    def test_file_errors_are_controlled(self):
        with self.assertRaises(KeystoreNotFoundError):
            self.keystore.load_and_decrypt_key(os.path.join(self.dir, "missing.json"), self.password)
        with self.assertRaises(KeystoreNotFoundError):
            self.keystore.load_and_decrypt_key(self.dir, self.password)     # a directory
        with self.assertRaises(KeystoreNotFoundError):
            self.keystore.read_metadata(os.path.join(self.dir, "missing.json"))

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0,
                         "POSIX permissions as a non-root user")
    def test_unreadable_file_is_controlled(self):
        os.chmod(self.path, 0o000)
        try:
            with self.assertRaises(KeystoreError):
                self.unlock()
        finally:
            os.chmod(self.path, 0o600)

    def test_errors_are_specific_vault_errors_without_internal_cause(self):
        attempts = {
            "wrong_password": lambda: self.keystore.load_and_decrypt_key(self.path, "wrong passphrase!!"),
            "password_not_string": lambda: self.keystore.load_and_decrypt_key(self.path, None),
        }
        for name, attempt in attempts.items():
            with self.subTest(case=name):
                with self.assertRaises(KeystoreAuthError) as ctx:
                    attempt()
                self.assertIsInstance(ctx.exception, VaultError)
                self.assertIsInstance(ctx.exception, ValueError)
                self.assertIsNone(ctx.exception.__cause__)
                self.assertNotIn("InvalidTag", str(ctx.exception))


class TestPasswordPolicy(_Base):

    def test_weak_passwords_rejected(self):
        weak = ["short", "password1234", "PASSWORD1234", "123456789012", "aaaaaaaaaaaaaaa",
                "abababababababab", "abcdefghijklmn", "987654321098", "contrasena123"]
        for i, password in enumerate(weak):
            with self.subTest(password=password):
                with self.assertRaises(WeakPasswordError):
                    self.keystore.encrypt_and_save_key(self.key, password, "Alice", "P-256",
                                                       os.path.join(self.dir, f"weak{i}.json"))
                self.assertFalse(os.path.exists(os.path.join(self.dir, f"weak{i}.json")))

    def test_strong_passwords_accepted(self):
        for i, password in enumerate(["correct horse battery staple", "Tr0ub4dor&3-xyz", "mi gato se llama Pepe"]):
            with self.subTest(password=password):
                self.keystore.encrypt_and_save_key(self.key, password, "Alice", "P-256",
                                                   os.path.join(self.dir, f"ok{i}.json"))

    def test_change_password_applies_policy(self):
        with self.assertRaises(WeakPasswordError):
            self.keystore.change_password(self.path, self.password, "123456789012")
        self.unlock()      # still works with the old password


class TestBackupAndRecovery(_Base):

    def test_backup_is_identical_copy_and_never_overwritten(self):
        usb = os.path.join(self.dir, "usb")
        first = self.keystore.backup_keystore(self.path, usb)
        second = self.keystore.backup_keystore(self.path, usb)      # same second -> new name
        self.assertNotEqual(first, second)
        for backup in (first, second):
            self.assertEqual(open(backup, "rb").read(), open(self.path, "rb").read())

    def test_restore_verifies_expected_fingerprint(self):
        """Key-identity verification: a valid backup of ANOTHER key is refused."""
        usb = os.path.join(self.dir, "usb")
        other_path = os.path.join(self.dir, "other.json")
        self.keystore.encrypt_and_save_key(ec.generate_private_key(ec.SECP256R1()), self.password,
                                           "Alice", "P-256", other_path)
        wrong_backup = self.keystore.backup_keystore(other_path, usb)
        dest = os.path.join(self.dir, "restored.json")
        expected = public_key_fingerprint(self.key.public_key())

        with self.assertRaises(KeystoreError):
            self.keystore.restore_keystore(wrong_backup, self.password, dest, expected_fingerprint=expected)
        self.assertFalse(os.path.exists(dest))

        good_backup = self.keystore.backup_keystore(self.path, usb)
        meta = self.keystore.restore_keystore(good_backup, self.password, dest, expected_fingerprint=expected)
        self.assertEqual(meta["public_key_fingerprint"], expected)

    def test_restore_from_missing_backup_is_controlled(self):
        with self.assertRaises(KeystoreNotFoundError):
            self.keystore.restore_keystore(os.path.join(self.dir, "nope.json"), self.password,
                                           os.path.join(self.dir, "dest.json"))

    def test_full_recovery_after_losing_the_keystore(self):
        backup = self.keystore.backup_keystore(self.path, os.path.join(self.dir, "usb"))
        os.remove(self.path)
        with self.assertRaises(KeystoreNotFoundError):
            self.unlock()
        self.keystore.restore_keystore(backup, self.password, self.path,
                                       expected_fingerprint=public_key_fingerprint(self.key.public_key()))
        self.assertEqual(self.unlock().private_numbers().private_value, self.key.private_numbers().private_value)


if __name__ == "__main__":
    unittest.main()
