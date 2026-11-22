"""
Interactive command-line interface (menu) of the Secure Digital Document Vault.

    python vault_cli.py [--home vault_home]

Every option is one use case. The menu only asks for input and shows results; the
logic lives in vault/app.py (use cases) and vault/attack_lab.py (attack scenarios),
which are covered by the automated tests.

Only ASCII characters are printed, so the menu works in any terminal (including the
classic Windows console).
"""
import argparse
import getpass
import os
import subprocess
import sys
from datetime import datetime

from vault.app import VaultApp
from vault.attack_lab import LAB_PASSWORDS, AttackLab, Outcome
from vault.errors import KeyChangedError, ReplayError, StaleContainerError, VaultError
from vault.keystore import DEFAULT_ITERATIONS, MIN_ITERATIONS

# src/vault/cli.py -> repository root (two levels above the package)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BackToMenu(Exception):
    """The user cancelled the current action."""


class VaultCLI:
    def __init__(self, app: VaultApp, lab: AttackLab, input_fn=input, password_fn=getpass.getpass,
                 out=print, color=None):
        self.app, self.lab = app, lab
        self.input_fn, self.password_fn, self.out = input_fn, password_fn, out
        self.color = sys.stdout.isatty() if color is None else color

    # ================================================================ output
    def _c(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def title(self, text):
        self.out("")
        self.out(self._c("1;96", "=" * 72))
        self.out(self._c("1;96", f"  {text}"))
        self.out(self._c("1;96", "=" * 72))

    def ok(self, text):
        self.out(self._c("92", f"  [ OK ] {text}"))

    def fail(self, text):
        self.out(self._c("91", f"  [FAIL] {text}"))

    def info(self, text=""):
        self.out(f"  {text}")

    def warn(self, text):
        self.out(self._c("93", f"  [ !! ] {text}"))

    def step(self, s):
        marker = self._c("92", "[ OK ]") if s.ok else self._c("91", "[FAIL]")
        self.out(f"  {marker} {s.number}/{s.total} {s.text}")

    # ================================================================= input
    def ask(self, prompt, default=None, allow_empty=False):
        suffix = f" [{default}]" if default else ""
        value = self.input_fn(f"  {prompt}{suffix}: ").strip()
        if value == "" and default is not None:
            return default
        if value == "" and not allow_empty:
            raise BackToMenu()
        return value

    def ask_yes_no(self, prompt, default=False):
        value = self.input_fn(f"  {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if value == "" else value in ("y", "yes")

    def ask_password(self, prompt="Password"):
        value = self.password_fn(f"  {prompt} (not shown): ")
        if not value:
            raise BackToMenu()
        return value

    def ask_new_password(self, owner):
        self.info("Password policy: at least 12 characters, not a common password, no simple sequences.")
        self.info("A long passphrase is easiest, e.g. 'my cat sleeps on the keyboard'.")
        first = self.ask_password(f"New password for {owner}")
        if self.password_fn("  Repeat the password (not shown): ") != first:
            raise VaultError("The passwords do not match.")
        return first

    def choose(self, prompt, options, labels=None):
        """Numbered list; returns the chosen option. Empty input cancels."""
        if not options:
            raise VaultError("There is nothing to choose from.")
        for i, option in enumerate(options, 1):
            self.info(f"{i:>2}. {labels[i - 1] if labels else option}")
        value = self.ask(prompt)
        if not value.isdigit() or not 1 <= int(value) <= len(options):
            raise VaultError("Invalid option.")
        return options[int(value) - 1]

    def choose_many(self, prompt, options):
        for i, option in enumerate(options, 1):
            self.info(f"{i:>2}. {option}")
        value = self.ask(prompt)
        chosen = []
        for part in value.replace(" ", "").split(","):
            if not part.isdigit() or not 1 <= int(part) <= len(options):
                raise VaultError(f"Invalid option: {part}")
            chosen.append(options[int(part) - 1])
        return list(dict.fromkeys(chosen))

    def choose_user(self, prompt="Who are you?"):
        users = self.app.list_users()
        if not users:
            raise VaultError("There are no users yet: create one in 'Users and keys'.")
        return self.choose(prompt, users)

    def choose_kind(self):
        return self.choose("Which key?", ["encryption", "signing"],
                           ["encryption key (P-256, opens the files sent to you)",
                            "signing key (Ed25519, proves the files you send are yours)"])

    def ask_path(self, prompt):
        path = self.ask(prompt).strip().strip('"').strip("'")
        return os.path.abspath(os.path.expanduser(path))

    # ================================================================= menus
    def run(self):
        actions = {
            "1": ("Users and keys", self.menu_users),
            "2": ("Contacts (trusted public keys)", self.menu_contacts),
            "3": ("Send a file", self.send_file),
            "4": ("Receive / open a file", self.receive_file),
            "5": ("Inspect a package (.vault) without decrypting", self.inspect_package),
            "6": ("Attack lab (security tests, step by step)", self.menu_lab),
            "7": ("Run the automated test suite", self.run_tests),
        }
        while True:
            self.title("SECURE DIGITAL DOCUMENT VAULT")
            users = self.app.list_users()
            self.info(f"Data folder: {self.app.home}")
            self.info(f"Users: {', '.join(users) if users else '(none yet - start with option 1)'}")
            self.info(f"Packages in the shared folder: {len(self.app.list_shared())}")
            self.info()
            for key, (label, _) in actions.items():
                self.info(f"{key}. {label}")
            self.info("0. Exit")
            try:
                option = self.input_fn("\n  Choose an option: ").strip()
            except (EOFError, KeyboardInterrupt):
                option = "0"
            if option == "0":
                self.info("Bye.")
                return 0
            if option in actions:
                self._safely(actions[option][1])
            else:
                self.fail("Invalid option.")

    def _safely(self, action):
        """Runs one action; any expected error goes back to the menu with a clear message."""
        try:
            action()
        except BackToMenu:
            self.info("(cancelled)")
        except (EOFError, KeyboardInterrupt):
            self.out("")
            self.info("(cancelled)")
        except VaultError as e:
            self.fail(f"{type(e).__name__}: {e}")
        except OSError as e:
            self.fail(f"File error: {e.strerror or e}")
        self._pause()

    def _pause(self):
        try:
            self.input_fn("\n  Press Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            pass

    def _submenu(self, title, actions):
        while True:
            self.title(title)
            for key, (label, _) in actions.items():
                self.info(f"{key}. {label}")
            self.info("0. Back")
            try:
                option = self.input_fn("\n  Choose an option: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if option in ("0", ""):
                return
            if option in actions:
                self._safely(actions[option][1])
            else:
                self.fail("Invalid option.")

    # ========================================================= users / keys
    def menu_users(self):
        self._submenu("USERS AND KEYS", {
            "1": ("Create a user (generates P-256 and Ed25519 key pairs)", self.create_user),
            "2": ("Show my keys and fingerprints", self.show_keys),
            "3": ("Publish my public keys (bundle for my contacts)", self.publish_keys),
            "4": ("Change a keystore password", self.change_password),
            "5": ("Rotate a key (the old one keeps opening old files)", self.rotate_key),
            "6": ("Mark a key as COMPROMISED (stolen laptop...)", self.mark_compromised),
            "7": ("Replace a compromised key with a new one", self.replace_compromised),
            "8": ("Back up my keystores", self.backup),
            "9": ("Restore a keystore from a backup", self.restore),
        })

    def create_user(self):
        self.title("CREATE A USER")
        name = self.ask("User name (letters, digits, - _ .)")
        password = self.ask_new_password(name)
        self.info("Generating keys and deriving the keystore key (PBKDF2, 600,000 iterations)...")
        fps = self.app.create_user(name, password)
        self.ok(f"User {name} created.")
        self.info(f"Encryption key (P-256)  fingerprint: {fps['encryption']}")
        self.info(f"Signing key (Ed25519)   fingerprint: {fps['signing']}")
        self.info("Private keys are stored ONLY encrypted in users/{}/keys/.".format(name))
        self.info(f"Public bundle published: public/{name}.pub.json  (give it to your contacts)")
        self.info("Your contacts must confirm these fingerprints with you through another channel.")

    def show_keys(self):
        name = self.choose_user()
        self.title(f"KEYS OF {name}")
        for row in self.app.key_report(name):
            self.info(f"{row['file']:<38} {row['key_type']:<8} {row['purpose']:<10} status={row['status']}")
            self.info(f"    fingerprint {row['public_key_fingerprint']}")
            self.info(f"    created {row['created_at']}   expires {row['expires_at'] or 'never'}")
        self.info("(Metadata is readable without the password; it is authenticated when the key is unlocked.)")

    def publish_keys(self):
        name = self.choose_user()
        path = self.app.publish_bundle(name)
        self.ok(f"Public bundle written to {path}")
        fps = self.app.fingerprints(name)
        self.info(f"Encryption fingerprint: {fps['encryption']}")
        self.info(f"Signing fingerprint:    {fps['signing']}")

    def change_password(self):
        name = self.choose_user()
        kind = self.choose_kind()
        old = self.ask_password(f"CURRENT password of {name}")
        new = self.ask_new_password(name)
        self.app.change_password(name, kind, old, new)
        self.ok("Password changed (new salt and nonce; the same private key, re-encrypted).")

    def rotate_key(self):
        name = self.choose_user()
        kind = self.choose_kind()
        password = self.ask_password(f"Password of {name}")
        fp = self.app.rotate_key(name, kind, password)
        self.ok(f"New active {kind} key: {fp}")
        self.info("The old key was moved to keys/retired/: it can still open OLD files.")
        self.warn("Your bundle was re-published: your contacts must import it again and accept the change.")

    def mark_compromised(self):
        name = self.choose_user()
        kind = self.choose_kind()
        if not self.ask_yes_no(f"Mark the {kind} key of {name} as COMPROMISED? It can never be used again"):
            raise BackToMenu()
        fp = self.app.mark_compromised(name, kind, self.ask_password(f"Password of {name}"))
        self.ok(f"Key {fp[:30]}... marked as compromised.")
        self.warn("Tell your contacts to REVOKE this key (Contacts > Revoke), then use option 7 for a new key.")

    def replace_compromised(self):
        name = self.choose_user()
        kind = self.choose_kind()
        password = self.ask_new_password(name)
        fp = self.app.replace_compromised_key(name, kind, password)
        self.ok(f"New {kind} key: {fp}")
        self.warn("Your bundle was re-published: your contacts must import it again.")

    def backup(self):
        name = self.choose_user()
        default = os.path.join(self.app.home, "backups", name)
        dest = self.ask("Backup folder (e.g. a USB drive)", default=default)
        for path in self.app.backup(name, os.path.abspath(os.path.expanduser(dest))):
            self.ok(f"Encrypted backup verified: {path}")
        self.info("The backups stay encrypted: the password is needed to use them, and it cannot be recovered.")

    def restore(self):
        name = self.choose_user()
        kind = self.choose_kind()
        backup = self.ask_path("Path of the backup file")
        overwrite = os.path.exists(self.app.key_path(name, kind)) and \
            self.ask_yes_no("A keystore already exists. Replace it with the backup?")
        meta = self.app.restore(name, kind, backup, self.ask_password(f"Password of the backup"), overwrite)
        self.ok(f"Backup verified (password, integrity, expected key) and restored: {meta['public_key_fingerprint']}")

    # ============================================================== contacts
    def menu_contacts(self):
        self._submenu("CONTACTS (TRUSTED PUBLIC KEYS)", {
            "1": ("Import a contact's public keys", self.import_contact),
            "2": ("List my contacts and their keys", self.list_contacts),
            "3": ("Revoke a contact's key (reported compromised)", self.revoke_contact),
        })

    def import_contact(self):
        user = self.choose_user()
        bundles = self.app.list_bundles()
        self.info("Public bundles available in the public/ folder (or choose 'other file'):")
        choice = self.choose("Bundle to import", bundles + ["other file..."])
        path = self.ask_path("Path of the bundle") if choice == "other file..." \
            else os.path.join(self.app.public_dir, choice)
        bundle = self.app.preview_bundle(path)
        self.title(f"PUBLIC KEYS OF '{bundle['name']}'")
        self.info(f"Encryption fingerprint: {bundle['encryption_fingerprint']}")
        self.info(f"Signing fingerprint:    {bundle['signing_fingerprint']}")
        self.warn("Anybody can create a bundle with any name. Compare these fingerprints with the")
        self.warn("owner through another channel (in person, phone call) before trusting them.")
        expected = self.ask("Paste the SIGNING fingerprint the owner gave you (Enter to skip)", allow_empty=True)
        if not expected and not self.ask_yes_no("Did you confirm the fingerprints with the owner?"):
            raise BackToMenu()
        try:
            result = self.app.import_contact(user, path, None, expected or None)
        except KeyChangedError as e:
            self.warn(str(e))
            if not self.ask_yes_no("Accept the NEW keys (only after confirming them with the owner)?"):
                raise BackToMenu()
            result = self.app.import_contact(user, path, None, expected or None, accept_key_change=True)
        self.ok(f"Contact '{bundle['name']}': {result}.")

    def list_contacts(self):
        user = self.choose_user()
        self.title(f"CONTACTS OF {user}")
        for c in self.app.contacts(user):
            self.info(c["name"] + ("  (you)" if c["name"] == user else ""))
            for kind in ("encryption", "signing"):
                for e in c[kind]:
                    self.info(f"    {kind:<10} {e['status']:<8} {e['fingerprint']}")

    def revoke_contact(self):
        user = self.choose_user()
        contact = self.choose("Contact", [c["name"] for c in self.app.contacts(user)])
        kind = self.choose("Which key?", ["signing", "encryption", "all"])
        if not self.ask_yes_no(f"Revoke the {kind} key(s) of {contact}? Revoked keys are refused FOREVER"):
            raise BackToMenu()
        n = self.app.revoke_contact(user, contact, kind)
        self.ok(f"{n} key(s) revoked. Packages signed with them will be rejected, even old ones.")

    # ================================================================= files
    def send_file(self):
        self.title("SEND A FILE")
        sender = self.choose_user("Sender (you)")
        path = self.ask_path("Path of the file to send")
        contacts = [c["name"] for c in self.app.contacts(sender) if c["name"] != sender]
        if not contacts:
            raise VaultError(f"{sender} has no contacts yet: import their public keys first (Contacts).")
        recipients = self.choose_many("Recipients (numbers separated by commas, e.g. 1,2)", contacts)
        include_self = self.ask_yes_no("Also encrypt it for yourself (so you can open it later)?", default=True)
        password = self.ask_password(f"Password of {sender} (to unlock the signing key)")
        self.info()
        out = self.app.send_file(sender, password, path, recipients, include_self, progress=self.step)
        self.ok(f"Package ready in the shared folder: {out}")
        self.info("The shared folder is UNTRUSTED: anybody may read or modify what is there.")

    def _choose_package(self):
        packages = self.app.list_shared()
        choice = self.choose("Package", packages + ["other file..."])
        return self.ask_path("Path of the .vault") if choice == "other file..." \
            else os.path.join(self.app.shared_dir, choice)

    def receive_file(self):
        self.title("RECEIVE / OPEN A FILE")
        user = self.choose_user("Recipient (you)")
        path = self._choose_package()
        sender = self.choose("Who do you expect it FROM?", [c["name"] for c in self.app.contacts(user)])
        password = self.ask_password(f"Password of {user} (to unlock your encryption key)")
        self.info()
        try:
            out = self.app.receive_file(user, password, path, sender, progress=self.step)
        except VaultError as e:
            already_received = isinstance(e, ReplayError) and not isinstance(e, StaleContainerError)
            if already_received and self.ask_yes_no(
                    "You already received this package. Open it again anyway?"):
                out = self.app.receive_file(user, password, path, sender, allow_reopen=True, progress=self.step)
            else:
                raise
        self.ok(f"File saved in {out}")
        self._preview(out)

    def _preview(self, path):
        with open(path, "rb") as f:
            data = f.read(400)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return
        if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            self.info("Content preview:")
            for line in text.splitlines()[:8]:
                self.info(f"    | {line}")

    def inspect_package(self):
        self.title("INSPECT A PACKAGE")
        path = self._choose_package()
        c = self.app.inspect(path)
        meta = c["metadata"]
        self.warn("NOT VERIFIED: this is what anyone with access to the storage can see.")
        self.info(f"Format / version : {c['format']} v{c['version']}")
        self.info(f"File name        : {meta['filename']}")
        self.info(f"Signed at        : {datetime.fromtimestamp(meta['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        self.info(f"Algorithms       : {meta['algorithm']} | {meta['key_wrap']} | {meta['signature_algorithm']}")
        self.info(f"Declared signer  : {c['signer_id']}")
        self.info(f"Ciphertext       : {len(c['ciphertext']) * 3 // 4} bytes (Base64 in the file)")
        self.info("Recipients:")
        for r in c["recipients"]:
            self.info(f"    {r['id']:<12} {r['key_id']}")
        self.info("The content and the file key are encrypted: none of this reveals the file.")

    # ================================================================== lab
    def menu_lab(self):
        self.title("ATTACK LAB")
        self.info("Each scenario performs one attack from the threat model on a real package and")
        self.info("runs the real application flow, so you see which check stops it.")
        self.info(f"Sandbox: {self.lab.root}  (users Alice, Bob and Eve; it is recreated now)")
        self.info("Lab passwords: " + ", ".join(f"{u}='{p}'" for u, p in LAB_PASSWORDS.items()))
        if not self.ask_yes_no("Create the sandbox and start?", default=True):
            raise BackToMenu()
        self.info()
        self.lab.setup(log=self.ok)
        self._pause()
        while True:
            self.title("ATTACK LAB - SCENARIOS")
            for i, s in enumerate(self.lab.scenarios, 1):
                self.info(f"{i:>2}. [{s.threat:>3}] {s.title}")
            self.info(" A. Run ALL scenarios")
            self.info(" 0. Back")
            option = self.input_fn("\n  Choose a scenario: ").strip().upper()
            if option in ("0", ""):
                return
            if option == "A":
                results = [(s, self._run_scenario(s)) for s in self.lab.scenarios]
                self.title("ATTACK LAB - SUMMARY")
                for s, o in results:
                    (self.ok if o.blocked else self.fail)(f"[{s.threat:>3}] {s.title}")
                blocked = sum(o.blocked for _, o in results)
                self.info(f"{blocked}/{len(results)} attacks blocked.")
                self._pause()
            elif option.isdigit() and 1 <= int(option) <= len(self.lab.scenarios):
                self._run_scenario(self.lab.scenarios[int(option) - 1])
                self._pause()
            else:
                self.fail("Invalid option.")

    def _run_scenario(self, s):
        self.title(f"[{s.threat}] {s.title}")
        self.info(f"Attacker : {s.attacker}")
        self.info(f"Attack   : {s.change}")
        self.info(f"Defense  : {s.defense}")
        self.info()
        try:
            outcome = self.lab.run(s.key, progress=self.step)
        except VaultError as e:
            self.fail(f"Unexpected error: {type(e).__name__}: {e}")
            return Outcome(False, str(e))
        for line in outcome.details:
            self.info(line)
        if outcome.blocked:
            self.ok(f"ATTACK BLOCKED -> {outcome.verdict}")
        else:
            self.fail(f"ATTACK SUCCEEDED -> {outcome.verdict}")
        return outcome

    # ================================================================ tests
    def run_tests(self):
        self.title("AUTOMATED TEST SUITE")
        verbose = self.ask_yes_no("Show the name of every test?")
        self.info("Running: python -m unittest discover -s tests" + (" -v" if verbose else ""))
        self.info()
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests"] + (["-v"] if verbose else [])
        result = subprocess.run(cmd, cwd=REPO_ROOT)
        (self.ok if result.returncode == 0 else self.fail)(
            "All tests passed." if result.returncode == 0 else "Some tests failed (see above).")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Secure Digital Document Vault - interactive menu")
    parser.add_argument("--home", default="vault_home",
                        help="data folder for users, contacts and packages (default: vault_home)")
    args = parser.parse_args(argv)
    if os.name == "nt":
        os.system("")          # enables ANSI colors in the Windows console
    app = VaultApp(args.home, DEFAULT_ITERATIONS, MIN_ITERATIONS)
    lab = AttackLab(args.home, DEFAULT_ITERATIONS, MIN_ITERATIONS)
    try:
        return VaultCLI(app, lab).run()
    except KeyboardInterrupt:
        print("\n  Bye.")
        return 0
