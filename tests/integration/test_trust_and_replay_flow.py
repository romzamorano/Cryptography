"""
Integration tests - trust establishment, revocation and replay protection combined with
the full sharing flow (keystore D6 + encryption D3 + signatures D5 + trust store + replay guard).

Each user has their own trust store (contacts) and replay cache, as in the real application:
  * Public keys are exchanged as bundles and their fingerprints are checked.
  * The sender encrypts for the keys trusted for each contact.
  * The recipient verifies with the signing key trusted for the expected sender,
    refuses revoked keys, and refuses packages that are stale or already received.
"""
import base64
import json
import os
import unittest

from vault.errors import (ContactKeyRevokedError, KeyChangedError, RecipientError, ReplayError,
                          SignatureError, StaleContainerError, TrustStoreError)
from vault.replay_guard import DEFAULT_MAX_AGE, ReplayGuard
from vault.trust_store import TrustStore, export_public_bundle

from ._helpers import IntegrationTestCase


class TestTrustAndReplayFlow(IntegrationTestCase):

    def setUp(self):
        super().setUp()
        self.trust = {u.name: TrustStore(self.path(f"{u.name}_contacts.json"))
                      for u in (self.alice, self.bob, self.carol, self.eve)}
        self.replay = {u.name: ReplayGuard(self.path(f"{u.name}_replay.json"))
                       for u in (self.alice, self.bob, self.carol, self.eve)}
        # Out-of-band exchange: everybody imports Alice's and Bob's bundles, checking the fingerprints
        for owner in (self.alice, self.bob):
            bundle = self.bundle(owner)
            meta_enc = self.keystore.read_metadata(owner.enc_path)
            meta_sign = self.keystore.read_metadata(owner.sign_path)
            for user in (self.alice, self.bob, self.carol):
                if user is not owner:
                    self.trust[user.name].import_bundle(bundle, meta_enc["public_key_fingerprint"],
                                                        meta_sign["public_key_fingerprint"])

    def bundle(self, user):
        return export_public_bundle(user.name, user.enc_public_key, user.sign_public_key)

    # ------------------------------------------------------------ app-like flows
    def send(self, sender, to, content=b"quarterly report", name="report.vault"):
        """Sender encrypts for the TRUSTED keys of the contacts in `to`."""
        recipients = [self.trust[sender.name].encryption_recipient(r) for r in to]
        with self.keystore.unlocked_key(sender.sign_path, sender.password) as sign_key:
            data = self.vault.encrypt_file(content, recipients, "report.txt", signer_private_key=sign_key)
        return self.write(name, data)

    def receive(self, user, vault_path, expected_sender):
        """Recipient: trusted signer lookup -> verify -> replay check -> decrypt -> record."""
        data = self.read(vault_path)
        claimed_signer = self.vault.parse_container(data)["signer_id"]
        sender_key = self.trust[user.name].signing_key_for(expected_sender, claimed_signer)
        container = self.vault.verify_container(data, sender_key)
        self.replay[user.name].check(container)
        with self.keystore.unlocked_key(user.enc_path, user.password, allow_inactive=True) as key:
            plaintext = self.vault.decrypt_file(data, key, None, sender_key)
        self.replay[user.name].record(container)
        return plaintext

    # ------------------------------------------------------------------ tests
    def test_1_trusted_exchange_end_to_end(self):
        """Alice sends to Bob using only trusted keys (bundle + confirmed fingerprints); Bob receives it."""
        vault_path = self.send(self.alice, ["Bob"])
        self.assertEqual(self.receive(self.bob, vault_path, "Alice"), b"quarterly report")

    def test_2_unknown_sender_rejected(self):
        """Eve is not in Bob's contacts: her (valid) signature is not trusted as Alice's."""
        eve_trust = TrustStore(self.path("eve_view.json"))
        eve_trust.import_bundle(self.bundle(self.bob))
        with self.keystore.unlocked_key(self.eve.sign_path, self.eve.password) as k:
            data = self.vault.encrypt_file(b"pay Eve", [eve_trust.encryption_recipient("Bob")],
                                           signer_private_key=k)
        with self.assertRaises(SignatureError):
            self.receive(self.bob, self.write("eve.vault", data), "Alice")

    def test_3_key_substitution_attack_detected(self):
        """Eve publishes a bundle named 'Alice' with HER keys: Bob's trust store refuses the change."""
        fake = export_public_bundle("Alice", self.eve.enc_public_key, self.eve.sign_public_key)
        with self.assertRaises(KeyChangedError):
            self.trust["Bob"].import_bundle(fake)
        # And Carol, who expects Alice's real fingerprint, refuses it even as a new contact
        fresh = TrustStore(self.path("fresh.json"))
        with self.assertRaises(TrustStoreError):
            fresh.import_bundle(fake, expected_signing_fp=self.keystore.read_metadata(
                self.alice.sign_path)["public_key_fingerprint"])

    def test_4_fingerprint_mismatch_refused_before_encrypting(self):
        """If the key given for Bob is not the one confirmed for Bob, nothing is encrypted."""
        recipient = self.trust["Alice"].encryption_recipient("Bob")
        recipient["public_key"] = self.eve.enc_public_key        # substituted key
        with self.keystore.unlocked_key(self.alice.sign_path, self.alice.password) as k:
            with self.assertRaises(RecipientError):
                self.vault.encrypt_file(b"x", [recipient], signer_private_key=k)

    def test_5_revoked_sender_key_rejects_old_and_new_files(self):
        """Alice reports her signing key stolen: Bob revokes it; every file signed with it is refused."""
        old_vault = self.send(self.alice, ["Bob"], name="old.vault")
        self.trust["Bob"].revoke("Alice", "signing")
        with self.assertRaises(ContactKeyRevokedError):
            self.receive(self.bob, old_vault, "Alice")

    def test_6_revoked_recipient_key_cannot_receive_new_files(self):
        self.trust["Alice"].revoke("Bob", "encryption")
        with self.assertRaises(ContactKeyRevokedError):
            self.send(self.alice, ["Bob"])

    def test_7_sender_rotation_old_files_still_verify(self):
        """Alice rotates her signing key and re-publishes: Bob accepts the change after confirming it."""
        old_vault = self.send(self.alice, ["Bob"], name="before.vault")
        new_path = os.path.join(self.dir, "keystore", "Alice_ed25519_v2.json")
        self.keystore.rotate_key(self.alice.sign_path, self.alice.password, new_path, "Alice-sign-v2")
        self.alice.sign_path = new_path

        with self.assertRaises(KeyChangedError):
            self.trust["Bob"].import_bundle(self.bundle(self.alice))
        self.trust["Bob"].import_bundle(self.bundle(self.alice), accept_key_change=True)

        new_vault = self.send(self.alice, ["Bob"], content=b"after rotation", name="after.vault")
        self.assertEqual(self.receive(self.bob, new_vault, "Alice"), b"after rotation")
        self.assertEqual(self.receive(self.bob, old_vault, "Alice"), b"quarterly report")   # retired key

    def test_8_replayed_package_rejected(self):
        """The attacker re-delivers the same package: the second delivery is refused."""
        vault_path = self.send(self.alice, ["Bob"])
        self.receive(self.bob, vault_path, "Alice")
        replayed = self.write("replayed_copy.vault", self.read(vault_path))
        with self.assertRaises(ReplayError):
            self.receive(self.bob, replayed, "Alice")

    def test_9_replay_cache_is_per_recipient(self):
        """Bob having received the package does not prevent Carol from receiving it."""
        self.trust["Alice"].import_bundle(self.bundle(self.carol))
        vault_path = self.send(self.alice, ["Bob", "Carol"])
        self.receive(self.bob, vault_path, "Alice")
        self.assertEqual(self.receive(self.carol, vault_path, "Alice"), b"quarterly report")

    def test_10_stale_package_rejected(self):
        """A genuine package signed long ago (outside the window) is refused."""
        vault_path = self.send(self.alice, ["Bob"])
        ts = json.loads(self.read(vault_path))["metadata"]["timestamp"]
        self.replay["Bob"] = ReplayGuard(self.path("Bob_replay.json"), clock=lambda: ts + DEFAULT_MAX_AGE + 1)
        with self.assertRaises(StaleContainerError):
            self.receive(self.bob, vault_path, "Alice")

    def test_11_failed_package_is_not_recorded(self):
        """A tampered package is rejected and NOT stored, so the genuine one is still accepted later."""
        vault_path = self.send(self.alice, ["Bob"])
        c = json.loads(self.read(vault_path))
        raw = bytearray(base64.b64decode(c["ciphertext"]))
        raw[0] ^= 1
        c["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(SignatureError):
            self.receive(self.bob, self.write("bad.vault", json.dumps(c).encode()), "Alice")
        self.assertEqual(self.receive(self.bob, vault_path, "Alice"), b"quarterly report")


if __name__ == "__main__":
    unittest.main()
