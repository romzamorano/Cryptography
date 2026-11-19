"""
Trust store unit tests: trust establishment for signing/encryption keys, key-change
detection, rotation (retired keys) and revocation (D5 / D6 feedback).
"""
import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from vault.crypto_module import SecureEncryptionModule
from vault.errors import (ContactKeyRevokedError, ContactNotFoundError, KeyChangedError,
                          SignatureError, TrustStoreError)
from vault.trust_store import TrustStore, export_public_bundle, load_public_bundle

fp = SecureEncryptionModule.key_fingerprint


def new_keys():
    enc = ec.generate_private_key(ec.SECP256R1()).public_key()
    _, sign = SecureEncryptionModule.generate_signing_keypair()
    return enc, sign


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "contacts.json")
        self.store = TrustStore(self.path)
        self.alice_enc, self.alice_sign = new_keys()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestPublicBundles(_Base):

    def test_bundle_roundtrip(self):
        bundle = load_public_bundle(export_public_bundle("Alice", self.alice_enc, self.alice_sign))
        self.assertEqual(bundle["name"], "Alice")
        self.assertEqual(bundle["encryption_fingerprint"], fp(self.alice_enc))
        self.assertEqual(bundle["signing_fingerprint"], fp(self.alice_sign))

    def test_bundle_with_wrong_fingerprint_rejected(self):
        data = json.loads(export_public_bundle("Alice", self.alice_enc, self.alice_sign))
        data["signing_fingerprint"] = "ed25519:" + "0" * 64
        with self.assertRaises(TrustStoreError):
            load_public_bundle(json.dumps(data).encode())

    def test_bundle_with_swapped_key_types_rejected(self):
        data = json.loads(export_public_bundle("Alice", self.alice_enc, self.alice_sign))
        data["encryption_key"], data["signing_key"] = data["signing_key"], data["encryption_key"]
        with self.assertRaises(TrustStoreError):
            load_public_bundle(json.dumps(data).encode())

    def test_malformed_bundles_rejected(self):
        good = json.loads(export_public_bundle("Alice", self.alice_enc, self.alice_sign))
        cases = {
            "not_json": b"hello",
            "empty": b"",
            "missing_field": json.dumps({k: v for k, v in good.items() if k != "signing_key"}).encode(),
            "bad_pem": json.dumps(dict(good, encryption_key="-----BEGIN PUBLIC KEY-----xx")).encode(),
            "bad_name": json.dumps(dict(good, name="../../etc")).encode(),
            "wrong_format": json.dumps(dict(good, format="OTHER")).encode(),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(TrustStoreError):
                    load_public_bundle(data)


class TestTrustEstablishment(_Base):

    def test_add_contact_and_persist(self):
        self.assertEqual(self.store.add_contact("Alice", self.alice_enc, self.alice_sign), "added")
        reloaded = TrustStore(self.path)
        self.assertEqual(reloaded.names(), ["Alice"])
        self.assertEqual(fp(reloaded.active_signing_key("Alice")), fp(self.alice_sign))
        self.assertEqual(reloaded.encryption_recipient("Alice")["fingerprint"], fp(self.alice_enc))

    def test_expected_fingerprints_are_enforced(self):
        """The user typed the fingerprints Alice read to them by phone: a substituted key is refused."""
        eve_enc, eve_sign = new_keys()
        with self.assertRaises(TrustStoreError):
            self.store.add_contact("Alice", eve_enc, eve_sign, expected_signing_fp=fp(self.alice_sign))
        self.assertEqual(self.store.names(), [])
        self.store.add_contact("Alice", self.alice_enc, self.alice_sign,
                               expected_encryption_fp=fp(self.alice_enc), expected_signing_fp=fp(self.alice_sign))
        self.assertEqual(self.store.names(), ["Alice"])

    def test_unknown_contact(self):
        with self.assertRaises(ContactNotFoundError):
            self.store.active_signing_key("Mallory")

    def test_re_importing_same_keys_is_unchanged(self):
        self.store.add_contact("Alice", self.alice_enc, self.alice_sign)
        self.assertEqual(self.store.add_contact("Alice", self.alice_enc, self.alice_sign), "unchanged")

    def test_key_change_refused_by_default(self):
        """Key-substitution protection: Eve publishes a bundle named 'Alice' with her keys."""
        self.store.add_contact("Alice", self.alice_enc, self.alice_sign)
        eve_enc, eve_sign = new_keys()
        with self.assertRaises(KeyChangedError):
            self.store.add_contact("Alice", eve_enc, eve_sign)
        self.assertEqual(fp(self.store.active_signing_key("Alice")), fp(self.alice_sign))

    def test_corrupted_trust_store_file_rejected(self):
        self.store.add_contact("Alice", self.alice_enc, self.alice_sign)
        with open(self.path) as f:
            data = json.load(f)
        data["contacts"]["Alice"]["signing"][0]["fingerprint"] = "ed25519:" + "1" * 64
        with open(self.path, "w") as f:
            json.dump(data, f)
        with self.assertRaises(TrustStoreError):
            TrustStore(self.path)


class TestRotationAndRevocation(_Base):

    def setUp(self):
        super().setUp()
        self.store.add_contact("Alice", self.alice_enc, self.alice_sign)

    def test_accepted_rotation_retires_old_keys(self):
        new_enc, new_sign = new_keys()
        self.assertEqual(self.store.add_contact("Alice", new_enc, new_sign, accept_key_change=True), "updated")
        # New files use the new key...
        self.assertEqual(self.store.encryption_recipient("Alice")["fingerprint"], fp(new_enc))
        # ...files signed with the old (retired) key still verify, with the new one too
        self.assertEqual(fp(self.store.signing_key_for("Alice", fp(self.alice_sign))), fp(self.alice_sign))
        self.assertEqual(fp(self.store.signing_key_for("Alice", fp(new_sign))), fp(new_sign))
        statuses = [e["status"] for e in self.store.entries("Alice", "signing")]
        self.assertEqual(statuses, ["retired", "active"])

    def test_signer_not_trusted_for_contact(self):
        _, eve_sign = new_keys()
        with self.assertRaises(SignatureError):
            self.store.signing_key_for("Alice", fp(eve_sign))

    def test_revoked_signing_key_refused(self):
        self.assertEqual(self.store.revoke("Alice", "signing"), 1)
        with self.assertRaises(ContactKeyRevokedError):
            self.store.signing_key_for("Alice", fp(self.alice_sign))
        with self.assertRaises(ContactKeyRevokedError):
            self.store.active_signing_key("Alice")
        self.assertTrue(TrustStore(self.path).is_revoked(fp(self.alice_sign)))      # persisted

    def test_revoked_encryption_key_cannot_receive_new_files(self):
        self.store.revoke("Alice", "encryption")
        with self.assertRaises(ContactKeyRevokedError):
            self.store.encryption_recipient("Alice")

    def test_revoked_key_can_never_be_trusted_again(self):
        self.store.revoke("Alice")
        with self.assertRaises(ContactKeyRevokedError):
            self.store.add_contact("Alice", self.alice_enc, self.alice_sign, accept_key_change=True)
        with self.assertRaises(ContactKeyRevokedError):
            self.store.add_contact("Alice2", self.alice_enc, self.alice_sign)

    def test_revoke_then_new_keys_after_confirmation(self):
        self.store.revoke("Alice")
        new_enc, new_sign = new_keys()
        self.store.add_contact("Alice", new_enc, new_sign, accept_key_change=True)
        self.assertEqual(self.store.encryption_recipient("Alice")["fingerprint"], fp(new_enc))
        with self.assertRaises(ContactKeyRevokedError):
            self.store.signing_key_for("Alice", fp(self.alice_sign))


if __name__ == "__main__":
    unittest.main()
