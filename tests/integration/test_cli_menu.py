"""
Integration tests - the interactive menu, driven with scripted keyboard input.

A complete session is simulated exactly as a user would type it: create users, exchange
public keys, send a file, receive it, try to receive it again (replay), inspect it and run
the attack lab. The output is checked for the expected messages.
"""
import os
import shutil
import tempfile
import unittest

from vault.app import VaultApp
from vault.attack_lab import AttackLab
from vault.cli import VaultCLI

ITER = 1000


class ScriptedCLI:
    """Feeds the menu with predefined answers and records everything it prints."""

    def __init__(self, home, answers, passwords):
        self.answers, self.passwords, self.output = list(answers), list(passwords), []
        app = VaultApp(home, ITER, ITER)
        lab = AttackLab(home, ITER, ITER)
        self.cli = VaultCLI(app, lab, input_fn=self._input, password_fn=self._password,
                            out=self.output.append, color=False)

    def _input(self, prompt):
        self.output.append(prompt)
        if not self.answers:
            raise EOFError          # nothing left to type -> the menu exits
        return self.answers.pop(0)

    def _password(self, prompt):
        self.output.append(prompt)
        return self.passwords.pop(0)

    def run(self):
        code = self.cli.run()
        return code, "\n".join(self.output)


class TestCliMenu(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vault-cli-")
        self.home = os.path.join(self.dir, "home")
        self.file = os.path.join(self.dir, "minutes.txt")
        with open(self.file, "w") as f:
            f.write("Meeting minutes: the project is on schedule.")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def create_users(self):
        answers = ["1", "1", "Alice", "", "1", "Bob", "", "0", "0"]
        passwords = ["alice menu passphrase", "alice menu passphrase", "bob menu passphrase", "bob menu passphrase"]
        return ScriptedCLI(self.home, answers, passwords).run()

    def exchange_keys(self):
        # Contacts > Import: Alice imports Bob (bundle 2 = Bob.pub.json), Bob imports Alice (bundle 1)
        answers = ["2", "1", "1", "2", "", "y", "",
                   "1", "2", "1", "", "y", "", "0", "0"]
        return ScriptedCLI(self.home, answers, []).run()

    def test_full_session_send_receive_replay_inspect(self):
        code, out = self.create_users()
        self.assertEqual(code, 0)
        self.assertIn("User Alice created.", out)
        self.assertIn("User Bob created.", out)

        code, out = self.exchange_keys()
        self.assertIn("Contact 'Bob': added.", out)
        self.assertIn("Contact 'Alice': added.", out)

        # Send: sender 1 (Alice), file, recipient 1 (Bob), include self (default yes)
        code, out = ScriptedCLI(self.home, ["3", "1", self.file, "1", "", "", "0"],
                                ["alice menu passphrase"]).run()
        self.assertIn("4/4 Package signed with Ed25519", out)
        self.assertIn("Package ready in the shared folder", out)

        # Receive: user 2 (Bob), package 1, expected sender 1 (Alice)
        code, out = ScriptedCLI(self.home, ["4", "2", "1", "1", "", "0"], ["bob menu passphrase"]).run()
        for n in range(1, 7):
            self.assertIn(f"[ OK ] {n}/6", out)
        self.assertIn("Meeting minutes: the project is on schedule.", out)

        # Same package again: replay detected, user declines to re-open
        code, out = ScriptedCLI(self.home, ["4", "2", "1", "1", "n", "", "0"], ["bob menu passphrase"]).run()
        self.assertIn("[FAIL] 4/6 Package rejected: it was already received", out)

        # Inspect
        code, out = ScriptedCLI(self.home, ["5", "1", "", "0"], []).run()
        self.assertIn("NOT VERIFIED", out)
        self.assertIn("minutes.txt", out)
        self.assertNotIn("on schedule", out)

    def test_wrong_expected_sender_is_rejected_in_menu(self):
        self.create_users()
        self.exchange_keys()
        ScriptedCLI(self.home, ["3", "1", self.file, "1", "", "", "0"], ["alice menu passphrase"]).run()
        # Bob opens it but says he expects it from himself (contact 2 = Bob): signature not trusted
        code, out = ScriptedCLI(self.home, ["4", "2", "1", "2", "", "0"], ["bob menu passphrase"]).run()
        self.assertIn("[FAIL] 2/6", out)
        self.assertNotIn("File saved", out)

    def test_invalid_options_and_cancel_do_not_crash(self):
        code, out = ScriptedCLI(self.home, ["9", "x", "3", "", "", "0"], []).run()
        self.assertEqual(code, 0)
        self.assertIn("Invalid option.", out)

    def test_weak_password_refused_in_menu(self):
        code, out = ScriptedCLI(self.home, ["1", "1", "Carol", "", "0", "0"],
                                ["123456789012", "123456789012"]).run()
        self.assertIn("WeakPasswordError", out)
        self.assertNotIn("User Carol created", out)

    def test_attack_lab_run_all_from_menu(self):
        code, out = ScriptedCLI(self.home, ["6", "", "", "A", "", "0", "", "0"], []).run()
        self.assertIn("17/17 attacks blocked.", out)
        self.assertNotIn("ATTACK SUCCEEDED", out)


if __name__ == "__main__":
    unittest.main()
