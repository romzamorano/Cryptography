"""
Integration tests - key lifecycle (D6) applied to real shared files (D3 + D5).

Checks that rotation, compromise, expiration, password change and backup/restore
behave correctly when the keys are actually used to open and sign files.
"""
import os
import unittest
from datetime import datetime, timedelta, timezone

from ._helpers import IntegrationTestCase


class TestKeyLifecycleFlow(IntegrationTestCase):

    def test_1_rotation_old_files_still_open_new_files_use_new_key(self):
        """Bob rotates his key: old files open with the retired key, new files with the new one."""
        old_vault = self.share_file(self.alice, self.write("old.txt", b"before rotation"),
                                    [self.bob], "old.vault")

        new_path = os.path.join(self.dir, "keystore", "Bob_p256_v2.json")
        new_pub = self.keystore.rotate_key(self.bob.enc_path, self.bob.password, new_path, "Bob-v2")

        # The retired key is refused for normal use...
        with self.assertRaises(ValueError):
            self.receive_file(self.bob, old_vault, self.alice)
        # ...but can still open OLD files when explicitly allowed
        self.assertEqual(self.read(self.receive_file(self.bob, old_vault, self.alice, allow_inactive=True)),
                         b"before rotation")

        # Alice encrypts a NEW file with Bob's NEW public key
        with self.keystore.unlocked_key(self.alice.sign_path, self.alice.password) as sign_key:
            container = self.vault.encrypt_file(b"after rotation", [{"id": "Bob-v2", "public_key": new_pub}],
                                                signer_private_key=sign_key)
        new_vault = self.write("new.vault", container)

        self.assertEqual(self.read(self.receive_file(self.bob, new_vault, self.alice,
                                                     key_path=new_path, key_id="Bob-v2")),
                         b"after rotation")
        # The OLD (retired) key cannot open files encrypted for the new key
        with self.assertRaises(ValueError):
            self.receive_file(self.bob, new_vault, self.alice, allow_inactive=True, key_id="Bob-v2")

    def test_2_compromised_recipient_key_cannot_open_files(self):
        """Bob's laptop is stolen: after marking his key as compromised it can open nothing."""
        vault_path = self.share_file(self.alice, self.write("doc.txt", b"shared before theft"), [self.bob])
        self.keystore.mark_compromised(self.bob.enc_path, self.bob.password)

        for allow in (False, True):
            with self.subTest(allow_inactive=allow):
                with self.assertRaises(ValueError):
                    self.receive_file(self.bob, vault_path, self.alice, allow_inactive=allow)

    def test_3_compromised_signing_key_cannot_sign(self):
        """Alice's signing key is compromised: she can no longer sign (share) new files."""
        self.keystore.mark_compromised(self.alice.sign_path, self.alice.password)
        with self.assertRaises(ValueError):
            self.share_file(self.alice, self.write("new.txt", b"x"), [self.bob])

    def test_4_expired_signing_key_cannot_sign(self):
        """An expired signing key cannot be used to create new signed files."""
        sign_key = self.keystore.load_and_decrypt_key(self.alice.sign_path, self.alice.password)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        self.keystore.encrypt_and_save_key(sign_key, self.alice.password, "Alice-sign", "Ed25519",
                                           self.alice.sign_path, expires_at=yesterday, overwrite=True)
        del sign_key
        with self.assertRaises(ValueError):
            self.share_file(self.alice, self.write("late.txt", b"x"), [self.bob])

    def test_5_backup_restore_then_open_previously_received_file(self):
        """Bob backs up his keystore, loses his computer, restores it and opens an old file."""
        vault_path = self.share_file(self.alice, self.write("contract.txt", b"signed contract"), [self.bob])
        backup = self.keystore.backup_keystore(self.bob.enc_path, os.path.join(self.dir, "usb"))

        os.remove(self.bob.enc_path)                                   # disk failure
        with self.assertRaises((ValueError, OSError)):
            self.receive_file(self.bob, vault_path, self.alice)

        self.keystore.restore_keystore(backup, self.bob.password, self.bob.enc_path)
        self.assertEqual(self.read(self.receive_file(self.bob, vault_path, self.alice)), b"signed contract")

    def test_6_tampered_backup_cannot_be_restored_or_used(self):
        """An attacker edits the backup on the USB drive: restore refuses it and nothing is written."""
        backup = self.keystore.backup_keystore(self.bob.enc_path, os.path.join(self.dir, "usb"))
        with open(backup, "r", encoding="utf-8") as f:
            content = f.read()
        with open(backup, "w", encoding="utf-8") as f:
            f.write(content.replace('"key_id": "Bob"', '"key_id": "Eve"'))

        dest = os.path.join(self.dir, "keystore", "Bob_restored.json")
        with self.assertRaises(ValueError):
            self.keystore.restore_keystore(backup, self.bob.password, dest)
        self.assertFalse(os.path.exists(dest))

    def test_7_password_change_keeps_access_to_files(self):
        """Bob changes his password: old password stops working, files still open with the new one."""
        vault_path = self.share_file(self.alice, self.write("doc.txt", b"still readable"), [self.bob])
        old_password = self.bob.password
        self.keystore.change_password(self.bob.enc_path, old_password, "bob brand new passphrase")

        with self.assertRaises(ValueError):
            self.receive_file(self.bob, vault_path, self.alice)       # still using the old password
        self.bob.password = "bob brand new passphrase"
        self.assertEqual(self.read(self.receive_file(self.bob, vault_path, self.alice)), b"still readable")

    def test_8_sender_identity_survives_keystore_restore(self):
        """Restoring Alice's signing keystore keeps the same identity: Bob still accepts her files."""
        fingerprint_before = self.keystore.read_metadata(self.alice.sign_path)["public_key_fingerprint"]
        backup = self.keystore.backup_keystore(self.alice.sign_path, os.path.join(self.dir, "usb"))
        os.remove(self.alice.sign_path)
        self.keystore.restore_keystore(backup, self.alice.password, self.alice.sign_path)

        self.assertEqual(self.keystore.read_metadata(self.alice.sign_path)["public_key_fingerprint"],
                         fingerprint_before)
        vault_path = self.share_file(self.alice, self.write("after.txt", b"after restore"), [self.bob])
        self.assertEqual(self.read(self.receive_file(self.bob, vault_path, self.alice)), b"after restore")


if __name__ == "__main__":
    unittest.main()
