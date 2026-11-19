"""
Hybrid encryption hardening (feedback D2 / D3):

  * Recipient identity is bound to the public key (key_id = SHA-256 fingerprint).
  * The ECIES capsule (ephemeral key, wrap nonce, wrapped DEK, tag) is strictly validated.
  * The key wrapping is bound to its context (recipient fingerprint, protocol version).
  * Malformed containers are rejected consistently with specific exceptions,
    and no plaintext or internal exception details are ever released.

To test the inner checks (capsule validation, context binding), some tests modify the
container AND re-sign it with the sender's real key: this simulates a malicious but
authenticated sender, or a bug, so the inner layers are exercised behind the signature.
"""
import base64
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vault.crypto_module import CAPSULE_SIZE, P256_POINT_SIZE, SecureEncryptionModule
from vault.errors import (AccessDeniedError, ContainerFormatError, IntegrityError,
                          RecipientError, SignatureError, VaultError)


def _flip(raw: bytes, index: int) -> bytes:
    data = bytearray(raw)
    data[index] ^= 0x01
    return bytes(data)


class _Base(unittest.TestCase):
    def setUp(self):
        self.vault = SecureEncryptionModule()
        self.plaintext = b"Quarterly results - confidential"
        self.alice_priv = ec.generate_private_key(ec.SECP256R1())
        self.bob_priv = ec.generate_private_key(ec.SECP256R1())
        self.carol_priv = ec.generate_private_key(ec.SECP256R1())
        self.eve_priv = ec.generate_private_key(ec.SECP256R1())
        self.sign_priv, self.sign_pub = SecureEncryptionModule.generate_signing_keypair()
        self.recipients = [
            {"id": "Bob", "public_key": self.bob_priv.public_key()},
            {"id": "Carol", "public_key": self.carol_priv.public_key()},
        ]
        self.container = self.vault.encrypt_file(self.plaintext, self.recipients, "q3.txt",
                                                 signer_private_key=self.sign_priv)

    def fp(self, priv):
        return SecureEncryptionModule.key_fingerprint(priv.public_key())

    def load(self):
        return json.loads(self.container)

    def resign(self, container: dict) -> bytes:
        """Re-signs a modified container with the sender's REAL key (bypasses the signature layer)."""
        container["signature"] = base64.b64encode(
            self.sign_priv.sign(self.vault._signed_digest(container))).decode("ascii")
        return json.dumps(container).encode("utf-8")

    def bob_decrypts(self, data):
        return self.vault.decrypt_file(data, self.bob_priv, None, self.sign_pub)


class TestRecipientKeyBinding(_Base):
    """Recipient identifiers are cryptographically linked to the public keys."""

    def test_key_id_is_fingerprint_of_public_key(self):
        entries = self.load()["recipients"]
        self.assertEqual([e["key_id"] for e in entries], [self.fp(self.bob_priv), self.fp(self.carol_priv)])
        self.assertTrue(all(e["key_id"].startswith("p256:") and len(e["key_id"]) == 5 + 64 for e in entries))

    def test_fingerprint_is_deterministic_and_matches_keystore(self):
        from vault.keystore import public_key_fingerprint
        pub = self.bob_priv.public_key()
        self.assertEqual(SecureEncryptionModule.key_fingerprint(pub), SecureEncryptionModule.key_fingerprint(pub))
        self.assertEqual(SecureEncryptionModule.key_fingerprint(pub), public_key_fingerprint(pub))

    def test_expected_fingerprint_mismatch_rejected_on_encrypt(self):
        """The caller expects Bob's fingerprint but passes Eve's key -> refused before encrypting."""
        with self.assertRaises(RecipientError):
            self.vault.encrypt_file(self.plaintext, [{"id": "Bob", "public_key": self.eve_priv.public_key(),
                                                      "fingerprint": self.fp(self.bob_priv)}],
                                    signer_private_key=self.sign_priv)

    def test_expected_fingerprint_match_accepted(self):
        data = self.vault.encrypt_file(self.plaintext, [{"id": "Bob", "public_key": self.bob_priv.public_key(),
                                                         "fingerprint": self.fp(self.bob_priv)}],
                                       signer_private_key=self.sign_priv)
        self.assertEqual(self.bob_decrypts(data), self.plaintext)

    def test_access_decided_by_key_not_by_label(self):
        """Eve claims the label 'Bob' with her own key: her fingerprint is not listed -> denied."""
        with self.assertRaises(AccessDeniedError):
            self.vault.decrypt_file(self.container, self.eve_priv, "Bob", self.sign_pub)
        with self.assertRaises(AccessDeniedError):
            self.vault.decrypt_file(self.container, self.eve_priv, self.fp(self.bob_priv), self.sign_pub)

    def test_label_or_fingerprint_accepted_as_key_id(self):
        self.assertEqual(self.vault.decrypt_file(self.container, self.bob_priv, "Bob", self.sign_pub), self.plaintext)
        self.assertEqual(self.vault.decrypt_file(self.container, self.bob_priv, self.fp(self.bob_priv),
                                                 self.sign_pub), self.plaintext)
        with self.assertRaises(AccessDeniedError):       # Bob's key, but claims to be Carol
            self.vault.decrypt_file(self.container, self.bob_priv, "Carol", self.sign_pub)

    def test_invalid_recipient_lists_rejected(self):
        bob = self.bob_priv.public_key()
        ed_priv, ed_pub = SecureEncryptionModule.generate_signing_keypair()
        cases = {
            "empty": [],
            "duplicated_label": [{"id": "Bob", "public_key": bob},
                                 {"id": "Bob", "public_key": self.carol_priv.public_key()}],
            "duplicated_key": [{"id": "Bob", "public_key": bob}, {"id": "Bob2", "public_key": bob}],
            "ed25519_key": [{"id": "Bob", "public_key": ed_pub}],
            "other_curve": [{"id": "Bob", "public_key": ec.generate_private_key(ec.SECP384R1()).public_key()}],
            "missing_key": [{"id": "Bob"}],
            "empty_label": [{"id": "", "public_key": bob}],
        }
        for name, recipients in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(RecipientError):
                    self.vault.encrypt_file(self.plaintext, recipients, signer_private_key=self.sign_priv)

    def test_non_p256_private_key_denied(self):
        ed_priv, _ = SecureEncryptionModule.generate_signing_keypair()
        with self.assertRaises(AccessDeniedError):
            self.vault.decrypt_file(self.container, ed_priv, None, self.sign_pub)


class TestCapsuleValidation(_Base):
    """Malformed or modified ECIES capsules are rejected before/at unwrapping."""

    def _with_bob_capsule(self, transform) -> bytes:
        c = self.load()
        raw = base64.b64decode(c["recipients"][0]["encrypted_key"])
        new = transform(raw)
        c["recipients"][0]["encrypted_key"] = new if isinstance(new, str) else base64.b64encode(new).decode()
        return self.resign(c)

    def test_capsule_has_fixed_size(self):
        for entry in self.load()["recipients"]:
            self.assertEqual(len(base64.b64decode(entry["encrypted_key"])), CAPSULE_SIZE)

    def test_structurally_invalid_capsules_rejected_as_format_errors(self):
        cases = {
            "truncated": lambda raw: raw[:-1],
            "extended": lambda raw: raw + b"\x00",
            "empty": lambda raw: b"",
            "invalid_base64": lambda raw: "@@not-base64@@",
            "compressed_point_prefix": lambda raw: b"\x02" + raw[1:],
            "point_not_on_curve": lambda raw: raw[:P256_POINT_SIZE - 1]
                                              + bytes([raw[P256_POINT_SIZE - 1] ^ 0x01]) + raw[P256_POINT_SIZE:],
        }
        for name, transform in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ContainerFormatError):
                    self.bob_decrypts(self._with_bob_capsule(transform))

    def test_modified_capsule_parts_rejected_as_integrity_errors(self):
        """Valid structure but modified content -> AES-GCM of the key wrap fails."""
        other_point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        cases = {
            "ephemeral_key_replaced": lambda raw: other_point + raw[P256_POINT_SIZE:],
            "wrap_nonce": lambda raw: _flip(raw, P256_POINT_SIZE),
            "wrapped_key": lambda raw: _flip(raw, P256_POINT_SIZE + 12),
            "wrap_tag": lambda raw: _flip(raw, CAPSULE_SIZE - 1),
        }
        for name, transform in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(IntegrityError):
                    self.bob_decrypts(self._with_bob_capsule(transform))

    def test_capsule_moved_to_other_recipient_rejected(self):
        """Context binding: Bob's capsule copied into Carol's entry cannot be opened by Carol
        (the KEK is derived with Carol's fingerprint in the HKDF info)."""
        c = self.load()
        c["recipients"][1]["encrypted_key"] = c["recipients"][0]["encrypted_key"]
        data = self.resign(c)
        with self.assertRaises(IntegrityError):
            self.vault.decrypt_file(data, self.carol_priv, None, self.sign_pub)

    def test_capsule_from_another_container_rejected(self):
        """A capsule from another file (different DEK) does not open this file."""
        other = json.loads(self.vault.encrypt_file(b"other", self.recipients, signer_private_key=self.sign_priv))
        c = self.load()
        c["recipients"][0]["encrypted_key"] = other["recipients"][0]["encrypted_key"]
        with self.assertRaises(IntegrityError):
            self.bob_decrypts(self.resign(c))

    def test_unmodified_capsule_tampering_detected_by_signature_first(self):
        """Without re-signing, any capsule change is caught by the signature (outer layer)."""
        c = self.load()
        raw = base64.b64decode(c["recipients"][0]["encrypted_key"])
        c["recipients"][0]["encrypted_key"] = base64.b64encode(_flip(raw, 70)).decode()
        with self.assertRaises(SignatureError):
            self.bob_decrypts(json.dumps(c).encode())


class TestMalformedContainers(_Base):
    """Malformed or incomplete containers -> ContainerFormatError, never a crash."""

    def test_malformed_container_bytes(self):
        cases = {
            "empty": b"",
            "not_json": b"hello",
            "not_utf8": b"\xff\xfe\xfd",
            "json_list": b"[1, 2, 3]",
            "json_string": b'"container"',
            "truncated": self.container[: len(self.container) // 2],
            "duplicated_keys": b'{"format": "SDDV", "format": "SDDV"}',
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ContainerFormatError):
                    self.bob_decrypts(data)

    def test_wrong_field_types_and_values(self):
        edits = {
            "version_string": lambda c: c.update(version="6"),
            "version_old": lambda c: c.update(version=5),
            "version_bool": lambda c: c.update(version=True),
            "unknown_algorithm": lambda c: c["metadata"].update(algorithm="AES-128-CBC"),
            "timestamp_string": lambda c: c["metadata"].update(timestamp="yesterday"),
            "metadata_extra_field": lambda c: c["metadata"].update(owner="Eve"),
            "recipients_not_list": lambda c: c.update(recipients={"Bob": "x"}),
            "recipients_empty": lambda c: c.update(recipients=[]),
            "recipient_missing_key_id": lambda c: c["recipients"][0].pop("key_id"),
            "recipient_extra_field": lambda c: c["recipients"][0].update(admin=True),
            "recipient_number_id": lambda c: c["recipients"][0].update(id=7),
            "nonce_wrong_length": lambda c: c.update(nonce=base64.b64encode(b"short").decode()),
            "tag_wrong_length": lambda c: c.update(tag=base64.b64encode(b"x" * 15).decode()),
            "ciphertext_not_base64": lambda c: c.update(ciphertext="***"),
        }
        for name, edit in edits.items():
            with self.subTest(case=name):
                c = self.load()
                edit(c)
                with self.assertRaises(ContainerFormatError):
                    self.bob_decrypts(self.resign(c))

    def test_signature_wrong_length_or_not_base64(self):
        for bad in ("AAAA", "!!!", base64.b64encode(b"x" * 65).decode()):
            with self.subTest(signature=bad):
                c = self.load()
                c["signature"] = bad
                with self.assertRaises(ContainerFormatError):
                    self.bob_decrypts(json.dumps(c).encode())

    def test_non_bytes_input_rejected(self):
        with self.assertRaises(ContainerFormatError):
            self.bob_decrypts(self.container.decode("utf-8"))

    def test_missing_sender_key_rejected(self):
        with self.assertRaises(SignatureError):
            self.vault.decrypt_file(self.container, self.bob_priv, "Bob", None)


class TestFailureHandling(_Base):
    """Failed decryption never releases plaintext nor internal exception details."""

    def test_all_failures_are_vault_errors_without_internal_cause(self):
        c = self.load()
        c["ciphertext"] = base64.b64encode(_flip(base64.b64decode(c["ciphertext"]), 0)).decode()
        attempts = {
            "tampered_ciphertext_resigned": lambda: self.bob_decrypts(self.resign(c)),
            "not_a_recipient": lambda: self.vault.decrypt_file(self.container, self.eve_priv, None, self.sign_pub),
            "garbage": lambda: self.bob_decrypts(b"\x00" * 50),
        }
        for name, attempt in attempts.items():
            with self.subTest(case=name):
                with self.assertRaises(VaultError) as ctx:
                    attempt()
                self.assertIsInstance(ctx.exception, ValueError)          # backwards compatible
                self.assertIsNone(ctx.exception.__cause__)                # raised "from None"
                self.assertTrue(ctx.exception.__suppress_context__ or ctx.exception.__context__ is None)
                self.assertNotIn("InvalidTag", str(ctx.exception))
                self.assertNotIn(self.plaintext.decode(), str(ctx.exception))

    def test_tampered_ciphertext_behind_valid_signature_releases_no_plaintext(self):
        """Even if the signature layer were bypassed, AES-GCM refuses to return any plaintext."""
        c = self.load()
        c["ciphertext"] = base64.b64encode(_flip(base64.b64decode(c["ciphertext"]), 3)).decode()
        result = None
        with self.assertRaises(IntegrityError):
            result = self.bob_decrypts(self.resign(c))
        self.assertIsNone(result)

    def test_explicit_timestamp_is_signed_and_validated(self):
        data = self.vault.encrypt_file(self.plaintext, self.recipients, signer_private_key=self.sign_priv,
                                       timestamp=1_700_000_000)
        self.assertEqual(self.vault.verify_container(data, self.sign_pub)["metadata"]["timestamp"], 1_700_000_000)
        for bad in (-1, "now", 1.5, True):
            with self.subTest(timestamp=bad):
                with self.assertRaises(ContainerFormatError):
                    self.vault.encrypt_file(self.plaintext, self.recipients, signer_private_key=self.sign_priv,
                                            timestamp=bad)

    def test_each_file_uses_a_fresh_file_key_and_nonce(self):
        """Random 96-bit nonces are safe here because every file key encrypts exactly one file."""
        a = json.loads(self.vault.encrypt_file(self.plaintext, self.recipients, signer_private_key=self.sign_priv))
        b = json.loads(self.vault.encrypt_file(self.plaintext, self.recipients, signer_private_key=self.sign_priv))
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])
        self.assertNotEqual(a["recipients"][0]["encrypted_key"], b["recipients"][0]["encrypted_key"])


if __name__ == "__main__":
    unittest.main()
