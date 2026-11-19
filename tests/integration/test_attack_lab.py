"""
Integration tests - the attack lab of the menu. Every scenario must be BLOCKED, and by
the expected defense (checked through the error type or the verdict).
"""
import shutil
import tempfile
import unittest

from vault.attack_lab import AttackLab

EXPECTED = {
    "read": "Only ciphertext",
    "bitflip": "SignatureError",
    "filename": "SignatureError",
    "add_recipient": "SignatureError",
    "remove_recipient": "SignatureError",
    "strip_signature": "SignatureError",
    "resign": "SignatureError",
    "non_recipient": "AccessDeniedError",
    "impersonate": "AccessDeniedError",
    "truncated": "ContainerFormatError",
    "replay": "ReplayError",
    "stale": "StaleContainerError",
    "revoked": "ContactKeyRevokedError",
    "substitution": "KeyChangedError",
    "stolen_keystore": "No guess unlocked",
    "tampered_keystore": "Every modification was rejected",
    "path_traversal": "inside Bob's inbox: True",
}


class TestAttackLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="vault-lab-")
        cls.lab = AttackLab(cls.dir, iterations=1000, min_iterations=1000)
        cls.lab.setup(log=lambda message: None)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_every_scenario_has_an_expectation(self):
        self.assertEqual({s.key for s in self.lab.scenarios}, set(EXPECTED))

    def test_every_attack_is_blocked_by_the_expected_defense(self):
        for scenario in self.lab.scenarios:
            with self.subTest(scenario=scenario.key):
                steps = []
                outcome = self.lab.run(scenario.key, progress=steps.append)
                self.assertTrue(outcome.blocked, outcome.verdict)
                self.assertIn(EXPECTED[scenario.key], outcome.verdict)

    def test_rejections_happen_before_decryption(self):
        """For tampered packages the failing step is the signature (3) - nothing is decrypted."""
        for key in ("bitflip", "filename", "add_recipient", "remove_recipient"):
            with self.subTest(scenario=key):
                steps = []
                self.lab.run(key, progress=steps.append)
                self.assertEqual((steps[-1].number, steps[-1].ok), (3, False))

    def test_genuine_package_still_accepted_by_bob(self):
        """The attacks on copies never damaged the original package (Bob may already have it)."""
        from vault.errors import ReplayError
        try:
            self.lab.app.receive_file("Bob", "bob lab passphrase", self.lab.package, "Alice")
        except ReplayError:
            pass


if __name__ == "__main__":
    unittest.main()
