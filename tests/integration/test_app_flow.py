"""
Integration tests - every use case of the application layer (vault/app.py), which is
exactly what the interactive menu calls: users, contacts, sending, receiving, key
lifecycle and safe file recovery.
"""
import os
import shutil
import tempfile
import unittest

from vault.app import VaultApp, sanitize_filename
from vault.errors import (AccessDeniedError, ContactKeyRevokedError, ContactNotFoundError, KeyChangedError,
                          KeyRevokedError, KeystoreAuthError, KeystoreError, KeystoreExistsError, ReplayError,
                          SignatureError, VaultError, WeakPasswordError)

TEST_ITERATIONS = 1000
PASSWORDS = {"Alice": "alice app passphrase", "Bob": "bob app passphrase", "Carol": "carol app passphrase"}


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vault-app-")
        self.app = VaultApp(os.path.join(self.dir, "home"), TEST_ITERATIONS, TEST_ITERATIONS)
        for name, password in PASSWORDS.items():
            self.app.create_user(name, password)
        # Everybody trusts everybody, with confirmed fingerprints
        for user in PASSWORDS:
            for other in PASSWORDS:
                if other != user:
                    self.app.import_contact(user, self.app.bundle_path(other),
                                            *self.app.fingerprints(other).values())
        self.source = self.make_file("report.txt", b"Quarterly report: all good.")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make_file(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def send(self, sender="Alice", to=("Bob",), path=None, **kw):
        return self.app.send_file(sender, PASSWORDS[sender], path or self.source, list(to), **kw)

    def receive(self, user, package, sender="Alice", **kw):
        return self.app.receive_file(user, PASSWORDS[user], package, sender, **kw)

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()


class TestUsersAndContacts(AppTestCase):

    def test_create_user_layout(self):
        home = self.app.home
        for rel in ("users/Alice/keys/encryption.json", "users/Alice/keys/signing.json",
                    "users/Alice/contacts.json", "public/Alice.pub.json"):
            self.assertTrue(os.path.exists(os.path.join(home, rel)), rel)
        self.assertEqual(self.app.list_users(), ["Alice", "Bob", "Carol"])
        for kind in ("encryption", "signing"):
            self.assertNotIn(b"PRIVATE KEY", self.read(self.app.key_path("Alice", kind)))

    def test_duplicate_user_and_weak_password_refused(self):
        with self.assertRaises(KeystoreExistsError):
            self.app.create_user("Alice", "another long passphrase")
        with self.assertRaises(WeakPasswordError):
            self.app.create_user("Dave", "123456789012")
        self.assertNotIn("Dave", self.app.list_users())
        self.assertFalse(os.path.exists(self.app.user_dir("Dave")))

    def test_invalid_user_names_refused(self):
        for bad in ("../evil", "", "a/b", ".hidden", "x" * 65):
            with self.subTest(name=bad):
                with self.assertRaises(VaultError):
                    self.app.create_user(bad, "a valid long passphrase")

    def test_contacts_include_self_and_confirmed_peers(self):
        names = [c["name"] for c in self.app.contacts("Alice")]
        self.assertEqual(names, ["Alice", "Bob", "Carol"])

    def test_import_with_wrong_expected_fingerprint_refused(self):
        self.app.create_user("Dave", "dave app passphrase")
        with self.assertRaises(VaultError):
            self.app.import_contact("Alice", self.app.bundle_path("Dave"), None, "ed25519:" + "0" * 64)
        self.assertNotIn("Dave", [c["name"] for c in self.app.contacts("Alice")])


class TestSendAndReceive(AppTestCase):

    def test_send_and_receive_with_reported_steps(self):
        send_steps, receive_steps = [], []
        package = self.send(progress=send_steps.append)
        self.assertTrue(package.startswith(self.app.shared_dir))
        out = self.receive("Bob", package, progress=receive_steps.append)
        self.assertEqual(self.read(out), self.read(self.source))
        self.assertEqual([s.number for s in send_steps], [1, 2, 3, 4])
        self.assertEqual([s.number for s in receive_steps], [1, 2, 3, 4, 5, 6])
        self.assertTrue(all(s.ok for s in send_steps + receive_steps))
        self.assertEqual(os.path.dirname(out), self.app.inbox_dir("Bob"))

    def test_sender_included_by_default(self):
        package = self.send()
        ids = [r["id"] for r in self.app.inspect(package)["recipients"]]
        self.assertEqual(ids, ["Alice", "Bob"])
        self.assertEqual(self.read(self.receive("Alice", package)), self.read(self.source))

    def test_multiple_recipients(self):
        package = self.send(to=("Bob", "Carol"), include_self=False)
        for user in ("Bob", "Carol"):
            self.assertEqual(self.read(self.receive(user, package)), self.read(self.source))
        with self.assertRaises(AccessDeniedError):
            self.receive("Alice", package)

    def test_failed_step_is_reported_and_nothing_written(self):
        package = self.send()
        steps = []
        with self.assertRaises(SignatureError):
            self.receive("Bob", package, sender="Carol", progress=steps.append)   # wrong expected sender
        self.assertFalse(steps[-1].ok)
        self.assertEqual(steps[-1].number, 2)
        self.assertEqual(os.listdir(self.app.inbox_dir("Bob")), [])

    def test_wrong_password_reported_and_package_not_recorded(self):
        package = self.send()
        with self.assertRaises(KeystoreAuthError):
            self.app.receive_file("Bob", "wrong passphrase!!", package, "Alice")
        self.assertEqual(self.read(self.receive("Bob", package)), self.read(self.source))   # not a replay

    def test_replay_rejected_unless_reopen_is_explicit(self):
        package = self.send()
        first = self.receive("Bob", package)
        with self.assertRaises(ReplayError):
            self.receive("Bob", package)
        second = self.receive("Bob", package, allow_reopen=True)
        self.assertNotEqual(first, second)                 # never overwrites: 'report (1).txt'
        self.assertEqual(self.read(first), self.read(second))

    def test_output_filename_is_sanitized(self):
        """Path traversal: the name inside the package cannot escape the inbox."""
        package = self.send(filename="../../evil.txt")
        out = self.receive("Bob", package)
        self.assertEqual(os.path.dirname(out), self.app.inbox_dir("Bob"))
        self.assertEqual(os.path.basename(out), "evil.txt")

    def test_sanitize_filename_cases(self):
        cases = {"../../etc/passwd": "passwd", "..\\..\\win.ini": "win.ini", ".bashrc": "bashrc",
                 "a<b>c.txt": "a_b_c.txt", "": "received_file", "...": "received_file",
                 "CON.txt": "_CON.txt", "report.pdf": "report.pdf", "x" * 300: "x" * 120}
        for given, expected in cases.items():
            with self.subTest(name=given[:20]):
                self.assertEqual(sanitize_filename(given), expected)

    def test_unknown_contact_and_missing_file(self):
        with self.assertRaises(ContactNotFoundError):
            self.send(to=("Mallory",))
        with self.assertRaises(VaultError):
            self.send(path=os.path.join(self.dir, "missing.txt"))

    def test_inspect_shows_header_without_plaintext(self):
        header = self.app.inspect(self.send())
        self.assertEqual(header["metadata"]["filename"], "report.txt")
        self.assertNotIn("Quarterly", str(header))


class TestKeyLifecycleInApp(AppTestCase):

    def test_rotation_keeps_old_files_and_requires_contacts_to_accept(self):
        old_package = self.send()
        self.app.rotate_key("Bob", "encryption", PASSWORDS["Bob"])
        # Alice still has Bob's OLD key: re-importing the new bundle warns about the change
        with self.assertRaises(KeyChangedError):
            self.app.import_contact("Alice", self.app.bundle_path("Bob"))
        self.app.import_contact("Alice", self.app.bundle_path("Bob"), accept_key_change=True)
        new_package = self.send(path=self.make_file("new.txt", b"after rotation"))
        self.assertEqual(self.read(self.receive("Bob", new_package)), b"after rotation")
        self.assertEqual(self.read(self.receive("Bob", old_package)), self.read(self.source))   # retired key
        self.assertEqual(len(os.listdir(self.app.retired_dir("Bob"))), 1)

    def test_signing_rotation_old_files_still_verify(self):
        old_package = self.send()
        self.app.rotate_key("Alice", "signing", PASSWORDS["Alice"])
        self.app.import_contact("Bob", self.app.bundle_path("Alice"), accept_key_change=True)
        self.assertEqual(self.read(self.receive("Bob", old_package)), self.read(self.source))
        self.assertEqual(self.read(self.receive("Bob", self.send(path=self.make_file("b.txt", b"b")))), b"b")

    def test_compromised_key_then_replacement(self):
        package = self.send()
        self.app.mark_compromised("Bob", "encryption", PASSWORDS["Bob"])
        with self.assertRaises(KeyRevokedError):
            self.receive("Bob", package)
        # Alice is told and revokes Bob's key: she cannot encrypt for it any more
        self.app.revoke_contact("Alice", "Bob", "encryption")
        with self.assertRaises(ContactKeyRevokedError):
            self.send()
        # Bob gets a new key; Alice imports it after confirming it
        self.app.replace_compromised_key("Bob", "encryption", PASSWORDS["Bob"])
        self.app.import_contact("Alice", self.app.bundle_path("Bob"), accept_key_change=True)
        self.assertEqual(self.read(self.receive("Bob", self.send(path=self.make_file("c.txt", b"c")))), b"c")

    def test_rotation_of_compromised_key_refused(self):
        self.app.mark_compromised("Bob", "signing", PASSWORDS["Bob"])
        with self.assertRaises(KeystoreError):
            self.app.rotate_key("Bob", "signing", PASSWORDS["Bob"])

    def test_backup_and_restore_with_expected_identity(self):
        package = self.send()
        backups = self.app.backup("Bob", os.path.join(self.dir, "usb"))
        self.assertEqual(len(backups), 2)
        os.remove(self.app.key_path("Bob", "encryption"))                  # lost
        enc_backup = next(b for b in backups if b.split(os.sep)[-1].startswith("Bob_"))
        self.app.restore("Bob", "encryption", enc_backup, PASSWORDS["Bob"])
        self.assertEqual(self.read(self.receive("Bob", package)), self.read(self.source))

    def test_restore_of_another_users_backup_refused(self):
        carol_backup = self.app.backup("Carol", os.path.join(self.dir, "usb"))
        enc = next(b for b in carol_backup if os.path.basename(b).startswith("Carol_"))
        with self.assertRaises(KeystoreError):
            self.app.restore("Bob", "encryption", enc, PASSWORDS["Carol"], overwrite=True)

    def test_change_password(self):
        self.app.change_password("Bob", "encryption", PASSWORDS["Bob"], "bob brand new passphrase")
        with self.assertRaises(KeystoreAuthError):
            self.receive("Bob", self.send())
        out = self.app.receive_file("Bob", "bob brand new passphrase", self.send(path=self.make_file("d.txt", b"d")),
                                    "Alice")
        self.assertEqual(self.read(out), b"d")


if __name__ == "__main__":
    unittest.main()
