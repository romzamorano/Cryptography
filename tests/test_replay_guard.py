"""
Replay protection unit tests: freshness window and seen-package cache.
"""
import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from vault.crypto_module import SecureEncryptionModule
from vault.errors import ReplayError, StaleContainerError
from vault.replay_guard import DEFAULT_MAX_AGE, ReplayGuard, container_id

DAY = 86400


class FakeClock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


class TestReplayGuard(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "replay.json")
        vault = SecureEncryptionModule()
        self.sign_priv, self.sign_pub = vault.generate_signing_keypair()
        bob = ec.generate_private_key(ec.SECP256R1())
        data = vault.encrypt_file(b"hello", [{"id": "Bob", "public_key": bob.public_key()}],
                                  signer_private_key=self.sign_priv)
        self.container = vault.verify_container(data, self.sign_pub)
        self.clock = FakeClock(self.container["metadata"]["timestamp"])
        self.guard = ReplayGuard(self.path, clock=self.clock)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_fresh_package_accepted_once(self):
        self.guard.check(self.container)
        self.guard.record(self.container)
        with self.assertRaises(ReplayError):
            self.guard.check(self.container)

    def test_seen_cache_is_persistent(self):
        self.guard.record(self.container)
        with self.assertRaises(ReplayError):
            ReplayGuard(self.path, clock=self.clock).check(self.container)

    def test_old_package_rejected(self):
        self.clock.now += DEFAULT_MAX_AGE + DAY
        with self.assertRaises(StaleContainerError):
            self.guard.check(self.container)

    def test_package_from_the_future_rejected(self):
        self.clock.now -= 3600
        with self.assertRaises(StaleContainerError):
            self.guard.check(self.container)

    def test_small_clock_difference_tolerated(self):
        self.clock.now -= 60
        self.guard.check(self.container)

    def test_stale_error_is_a_replay_error(self):
        self.assertTrue(issubclass(StaleContainerError, ReplayError))

    def test_cache_pruned_outside_window(self):
        self.guard.record(self.container)
        self.clock.now += DEFAULT_MAX_AGE + DAY
        other = dict(self.container, nonce="AAAAAAAAAAAAAAAA")
        other["metadata"] = dict(self.container["metadata"], timestamp=int(self.clock.now))
        self.guard.record(other)
        self.assertEqual(set(self.guard.seen), {container_id(other)})

    def test_id_independent_of_signature_and_changes_with_content(self):
        self.assertEqual(container_id(self.container), container_id(dict(self.container, signature="x")))
        self.assertNotEqual(container_id(self.container), container_id(dict(self.container, nonce="other")))

    def test_corrupted_cache_does_not_disable_protection(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        with self.assertRaises(ReplayError):
            ReplayGuard(self.path)
        with open(self.path, "w") as f:
            json.dump({"format": "OTHER"}, f)
        with self.assertRaises(ReplayError):
            ReplayGuard(self.path)


if __name__ == "__main__":
    unittest.main()
