"""
Integration tests - complete file sharing flow (D3 + D5 + D6).

Sender:    file on disk -> unlock signing key (keystore) -> encrypt + sign -> .vault on disk
Recipient: .vault on disk -> unlock own key (keystore) -> verify signature -> decrypt -> file on disk
"""
import json
import os
import unittest

from ._helpers import IntegrationTestCase


class TestFileSharingFlow(IntegrationTestCase):

    def test_1_alice_shares_file_with_bob_end_to_end(self):
        """Alice shares a file with Bob: Bob's output file is identical to Alice's original."""
        original = b"Confidential project report: launch date is 2026-12-01."
        input_path = self.write("report.txt", original)

        vault_path = self.share_file(self.alice, input_path, [self.alice, self.bob])
        output_path = self.receive_file(self.bob, vault_path, expected_sender=self.alice)

        self.assertEqual(self.read(output_path), original)

    def test_2_vault_file_on_disk_does_not_reveal_plaintext(self):
        """The .vault stored on disk does not contain the plaintext."""
        original = b"Top secret: the password of the server is hunter2."
        vault_path = self.share_file(self.alice, self.write("secret.txt", original), [self.bob])

        stored = self.read(vault_path)
        self.assertNotIn(original, stored)
        self.assertNotIn(b"hunter2", stored)

    def test_3_binary_large_and_empty_files_roundtrip(self):
        """Binary (all byte values), large (1 MiB) and empty files survive the full flow."""
        cases = {
            "binary.bin": bytes(range(256)) * 4,
            "large.bin": os.urandom(1024 * 1024),
            "empty.txt": b"",
        }
        for name, content in cases.items():
            with self.subTest(file=name):
                vault_path = self.share_file(self.alice, self.write(name, content), [self.bob],
                                             vault_name=f"{name}.vault")
                output = self.receive_file(self.bob, vault_path, self.alice, output_name=f"out_{name}")
                self.assertEqual(self.read(output), content)

    def test_4_three_recipients_each_decrypt_with_own_keystore(self):
        """Encrypted once for Alice, Bob and Carol: each one opens it with their own keystore."""
        original = b"Minutes of the team meeting."
        vault_path = self.share_file(self.alice, self.write("minutes.txt", original),
                                     [self.alice, self.bob, self.carol])

        for user in (self.alice, self.bob, self.carol):
            with self.subTest(recipient=user.name):
                output = self.receive_file(user, vault_path, self.alice, output_name=f"{user.name}.txt")
                self.assertEqual(self.read(output), original)

    def test_5_non_recipient_rejected_and_no_output_written(self):
        """Eve (not a recipient) is rejected, even impersonating Bob, and no output file is created."""
        vault_path = self.share_file(self.alice, self.write("doc.txt", b"for Bob only"), [self.bob])

        with self.assertRaises(ValueError):
            self.receive_file(self.eve, vault_path, self.alice, output_name="eve.txt")
        with self.assertRaises(ValueError):
            self.receive_file(self.eve, vault_path, self.alice, output_name="eve_as_bob.txt", key_id="Bob")

        self.assertFalse(os.path.exists(self.path("eve.txt")))
        self.assertFalse(os.path.exists(self.path("eve_as_bob.txt")))

    def test_6_container_metadata_matches_sender_and_recipients(self):
        """The stored container identifies the real signer and lists exactly the chosen recipients."""
        vault_path = self.share_file(self.alice, self.write("plan.txt", b"plan"), [self.bob, self.carol])
        container = self.vault.verify_container(self.read(vault_path), self.alice.sign_public_key)

        self.assertEqual(container["signer_id"],
                         self.keystore.read_metadata(self.alice.sign_path)["public_key_fingerprint"])
        self.assertEqual([r["id"] for r in container["recipients"]], ["Bob", "Carol"])
        self.assertEqual(container["metadata"]["filename"], "plan.txt")

    def test_7_each_share_produces_a_different_container(self):
        """Sharing the same file twice gives different file keys, nonces and ciphertexts."""
        input_path = self.write("same.txt", b"same content")
        first = json.loads(self.read(self.share_file(self.alice, input_path, [self.bob], "a.vault")))
        second = json.loads(self.read(self.share_file(self.alice, input_path, [self.bob], "b.vault")))

        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
        self.assertNotEqual(first["recipients"][0]["encrypted_key"], second["recipients"][0]["encrypted_key"])


if __name__ == "__main__":
    unittest.main()
