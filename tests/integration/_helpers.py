"""
Shared helpers for the integration tests.

Unlike the unit tests, these tests combine the three modules of the vault in the
same flow, using real files on disk:
  * D6 keystore      -> private keys are always taken from encrypted keystore files
  * D3 encryption    -> files are encrypted for one or more recipients
  * D5 signatures    -> the sender signs, the recipient verifies before decrypting

Each test works inside a temporary folder that is deleted at the end.
"""
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from vault.crypto_module import SecureEncryptionModule
from vault.keystore import SecureKeyStore

# Fast KDF ONLY for the tests (production default and minimum: 600,000 iterations)
TEST_ITERATIONS = 1000


class VaultUser:
    """A user of the vault: one P-256 key (encryption) and one Ed25519 key (signing),
    both stored ONLY in encrypted keystore files."""

    def __init__(self, name, password, keystore, folder):
        self.name = name
        self.password = password
        self.keystore = keystore
        self.enc_path = os.path.join(folder, "keystore", f"{name}_p256.json")
        self.sign_path = os.path.join(folder, "keystore", f"{name}_ed25519.json")

        # Keys are generated and saved encrypted; no plaintext private key is kept in memory
        keystore.encrypt_and_save_key(ec.generate_private_key(ec.SECP256R1()),
                                      password, name, "P-256", self.enc_path)
        sign_priv, _ = SecureEncryptionModule.generate_signing_keypair()
        keystore.encrypt_and_save_key(sign_priv, password, f"{name}-sign", "Ed25519", self.sign_path)

    # Public keys are read from the keystore metadata (no password needed)
    @property
    def enc_public_key(self):
        return self.keystore.load_public_key(self.enc_path)

    @property
    def sign_public_key(self):
        return self.keystore.load_public_key(self.sign_path)

    def as_recipient(self):
        return {"id": self.name, "public_key": self.enc_public_key}


class IntegrationTestCase(unittest.TestCase):
    """Base class: temporary folder, keystore, vault and the users Alice, Bob, Carol and Eve."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vault-integration-")
        self.keystore = SecureKeyStore(iterations=TEST_ITERATIONS, min_iterations=TEST_ITERATIONS)
        self.vault = SecureEncryptionModule()
        self.alice = VaultUser("Alice", "alice long passphrase", self.keystore, self.dir)
        self.bob = VaultUser("Bob", "bob long passphrase!!", self.keystore, self.dir)
        self.carol = VaultUser("Carol", "carol long passphrase", self.keystore, self.dir)
        self.eve = VaultUser("Eve", "eve long passphrase!!", self.keystore, self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    # ------------------------------------------------------------------ files
    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, data: bytes):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    def read(self, path) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    # ------------------------------------------------------------- workflows
    def share_file(self, sender, input_path, recipients, vault_name="shared.vault"):
        """Sender side: read file -> unlock signing key -> encrypt + sign -> save .vault"""
        plaintext = self.read(input_path)
        with self.keystore.unlocked_key(sender.sign_path, sender.password) as sign_key:
            container = self.vault.encrypt_file(
                plaintext, [r.as_recipient() for r in recipients],
                filename=os.path.basename(input_path), signer_private_key=sign_key)
        return self.write(vault_name, container)

    def receive_file(self, recipient, vault_path, expected_sender, output_name="received.bin",
                     allow_inactive=False, key_path=None, key_id=None):
        """Recipient side: read .vault -> unlock own key -> verify + decrypt -> save output.
        The output file is written ONLY if verification and decryption succeed."""
        container = self.read(vault_path)
        with self.keystore.unlocked_key(key_path or recipient.enc_path, recipient.password,
                                        allow_inactive=allow_inactive) as enc_key:
            plaintext = self.vault.decrypt_file(container, enc_key, key_id or recipient.name,
                                                expected_sender.sign_public_key)
        return self.write(output_name, plaintext)
