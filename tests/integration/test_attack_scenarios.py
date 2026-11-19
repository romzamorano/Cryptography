"""
Integration tests - attack scenarios from the threat model (D1) against the full system.

The attacker (Eve) has read/write access to the untrusted storage where the .vault files
and, in some scenarios, the keystore files are kept. She also has her own valid keys.
"""
import base64
import json
import os
import unittest

from ._helpers import IntegrationTestCase


def _flip_bit_b64(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class TestAttackScenarios(IntegrationTestCase):

    def setUp(self):
        super().setUp()
        self.original = b"Payroll 2026: confidential."
        self.vault_path = self.share_file(self.alice, self.write("payroll.txt", self.original),
                                          [self.alice, self.bob])

    def _edit_vault_on_disk(self, edit):
        """Simulates an attacker editing the .vault file directly in the shared folder."""
        container = json.loads(self.read(self.vault_path))
        edit(container)
        self.write(os.path.basename(self.vault_path), json.dumps(container).encode("utf-8"))

    def test_1_tampered_vault_on_disk_rejected_for_every_field(self):
        """Any field of the stored .vault modified on disk -> Bob rejects it."""
        edits = {
            "ciphertext": lambda c: c.update(ciphertext=_flip_bit_b64(c["ciphertext"])),
            "tag": lambda c: c.update(tag=_flip_bit_b64(c["tag"])),
            "nonce": lambda c: c.update(nonce=_flip_bit_b64(c["nonce"])),
            "filename": lambda c: c["metadata"].update(filename="invoice.exe"),
            "timestamp": lambda c: c["metadata"].update(timestamp=c["metadata"]["timestamp"] - 86400),
            "wrapped_key": lambda c: c["recipients"][1].update(
                encrypted_key=_flip_bit_b64(c["recipients"][1]["encrypted_key"])),
            "recipient_added": lambda c: c["recipients"].append(dict(c["recipients"][1], id="Eve")),
            "recipient_removed": lambda c: c["recipients"].pop(0),
            "signature": lambda c: c.update(signature=_flip_bit_b64(c["signature"])),
            "signature_removed": lambda c: c.pop("signature"),
        }
        pristine = self.read(self.vault_path)
        for name, edit in edits.items():
            with self.subTest(tampered=name):
                self.write(os.path.basename(self.vault_path), pristine)
                self._edit_vault_on_disk(edit)
                with self.assertRaises(ValueError):
                    self.receive_file(self.bob, self.vault_path, self.alice)

    def test_2_corrupted_or_truncated_vault_file_rejected(self):
        """Random corruption or truncation of the .vault file (not valid JSON anymore) -> rejected."""
        pristine = self.read(self.vault_path)
        corruptions = {
            "truncated": pristine[: len(pristine) // 2],
            "empty": b"",
            "garbage": os.urandom(256),
            "not_utf8": b"\xff\xfe" + pristine,
        }
        for name, data in corruptions.items():
            with self.subTest(corruption=name):
                self.write(os.path.basename(self.vault_path), data)
                with self.assertRaises(ValueError):
                    self.receive_file(self.bob, self.vault_path, self.alice)

    def test_3_eve_resigns_container_with_her_own_keystore_key(self):
        """Eve modifies the file and re-signs it with HER signing key (taken from her keystore):
        the signature is mathematically valid, but Bob expects Alice -> rejected."""
        container = json.loads(self.read(self.vault_path))
        container["metadata"]["filename"] = "malware.exe"
        container["signer_id"] = self.keystore.read_metadata(self.eve.sign_path)["public_key_fingerprint"]
        unsigned = {k: v for k, v in container.items() if k != "signature"}
        with self.keystore.unlocked_key(self.eve.sign_path, self.eve.password) as eve_sign_key:
            container["signature"] = base64.b64encode(
                eve_sign_key.sign(self.vault._signed_digest(unsigned))).decode("ascii")
        self.write(os.path.basename(self.vault_path), json.dumps(container).encode("utf-8"))

        # The signature itself is valid for Eve...
        self.vault.verify_container(self.read(self.vault_path), self.eve.sign_public_key)
        # ...but Bob verifies against Alice's trusted public key
        with self.assertRaises(ValueError):
            self.receive_file(self.bob, self.vault_path, expected_sender=self.alice)

    def test_4_file_from_another_sender_rejected(self):
        """Eve sends Bob a genuine file signed by herself, but Bob expects it from Alice -> rejected."""
        eve_vault = self.share_file(self.eve, self.write("fake.txt", b"pay to Eve"), [self.bob], "eve.vault")

        with self.assertRaises(ValueError):
            self.receive_file(self.bob, eve_vault, expected_sender=self.alice)
        # If Bob explicitly expects Eve, the file is authentic (it really comes from Eve)
        self.assertEqual(self.read(self.receive_file(self.bob, eve_vault, expected_sender=self.eve)),
                         b"pay to Eve")

    def test_5_stolen_keystore_and_vault_without_password(self):
        """Eve steals Bob's keystore AND the .vault: without Bob's password she cannot decrypt."""
        stolen_keystore = self.read(self.bob.enc_path)
        self.assertNotIn(b"PRIVATE KEY", stolen_keystore)

        for guess in ["123456", "password", "bob", "Bob2026", "bob long passphrase"]:
            with self.subTest(guess=guess):
                with self.assertRaises(ValueError):
                    with self.keystore.unlocked_key(self.bob.enc_path, guess):
                        pass

    def test_6_eve_cannot_use_her_keystore_on_bobs_entry(self):
        """Eve copies Bob's wrapped key entry and tries to open it with her own (valid) keystore."""
        with self.keystore.unlocked_key(self.eve.enc_path, self.eve.password) as eve_key:
            with self.assertRaises(ValueError):
                self.vault.decrypt_file(self.read(self.vault_path), eve_key, "Bob",
                                        self.alice.sign_public_key)

    def test_7_vault_moved_between_folders_still_verifies(self):
        """The untrusted channel only moves bytes: a copied/renamed .vault still opens for Bob."""
        moved = self.write("renamed_by_storage_provider.vault", self.read(self.vault_path))
        self.assertEqual(self.read(self.receive_file(self.bob, moved, self.alice)), self.original)


if __name__ == "__main__":
    unittest.main()
