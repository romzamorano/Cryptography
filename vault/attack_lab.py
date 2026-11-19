"""
Attack lab - the automated security tests, shown step by step.

The lab works in its own sandbox (vault_home/attack_lab/) with three users:
Alice (sender), Bob (recipient) and Eve (attacker). Alice sends Bob a real package;
then each scenario performs one attack from the threat model (D1, section 9) on a copy
of that package (or on a keystore / trust store) and runs the REAL application flow,
so the user sees exactly which check stops the attack.

Lab passwords are fixed and shown on screen: the lab is a demonstration, never use
these users for real files.
"""
import base64
import json
import os
import shutil
import time

from vault.app import VaultApp
from vault.errors import AccessDeniedError, VaultError
from vault.keystore import DEFAULT_ITERATIONS, MIN_ITERATIONS
from vault.trust_store import export_public_bundle

LAB_PASSWORDS = {"Alice": "alice lab passphrase", "Bob": "bob lab passphrase", "Eve": "eve lab passphrase"}
SECRET = b"CONFIDENTIAL - Payroll 2026: launch bonus approved for the whole team."
DAY = 86400


class Outcome:
    """Result of one scenario."""

    def __init__(self, blocked: bool, verdict: str, details=None):
        self.blocked = blocked              # True = the attack did not succeed
        self.verdict = verdict              # short explanation of what stopped it
        self.details = details or []        # extra lines to show


class Scenario:
    def __init__(self, key, title, threat, attacker, change, defense, run):
        self.key, self.title, self.threat = key, title, threat
        self.attacker, self.change, self.defense, self.run = attacker, change, defense, run


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _flip_b64(value: str, index: int = 0) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


class AttackLab:
    def __init__(self, home: str = "vault_home", iterations: int = DEFAULT_ITERATIONS,
                 min_iterations: int = MIN_ITERATIONS):
        self.root = os.path.join(os.path.abspath(home), "attack_lab")
        self.iterations, self.min_iterations = iterations, min_iterations
        self.app = None
        self.package = None
        self.scenarios = self._scenarios()

    # ------------------------------------------------------------------ setup
    def setup(self, log=print):
        """Fresh sandbox: users, public-key exchange and one genuine package from Alice to Bob."""
        if os.path.isdir(self.root):
            shutil.rmtree(self.root)
        self.app = VaultApp(self.root, self.iterations, self.min_iterations)
        app = self.app
        for name, password in LAB_PASSWORDS.items():
            fps = app.create_user(name, password)
            log(f"User {name} created  (encryption {fps['encryption'][:21]}..., signing {fps['signing'][:23]}...)")
        # Alice and Bob trust each other (fingerprints confirmed out of band)
        app.import_contact("Alice", app.bundle_path("Bob"), *app.fingerprints("Bob").values())
        app.import_contact("Bob", app.bundle_path("Alice"), *app.fingerprints("Alice").values())
        # Public bundles are public: Eve imports them too. Bob does NOT trust Eve.
        app.import_contact("Eve", app.bundle_path("Alice"))
        app.import_contact("Eve", app.bundle_path("Bob"))
        log("Alice and Bob exchanged public keys and confirmed fingerprints; Eve downloaded both public bundles.")
        source = os.path.join(self.root, "payroll.txt")
        with open(source, "wb") as f:
            f.write(SECRET)
        self.package = app.send_file("Alice", LAB_PASSWORDS["Alice"], source, ["Bob"])
        log(f"Alice sent payroll.txt to Bob -> shared/{os.path.basename(self.package)}")

    # ---------------------------------------------------------------- helpers
    def _container(self) -> dict:
        with open(self.package, "rb") as f:
            return json.loads(f.read())

    def _save_attack(self, name: str, data) -> str:
        path = os.path.join(self.app.shared_dir, f"attack_{name}.vault")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else json.dumps(data, indent=2).encode())
        return path

    def _bob_receives(self, path, progress, expected_sender="Alice") -> Outcome:
        try:
            out = self.app.receive_file("Bob", LAB_PASSWORDS["Bob"], path, expected_sender, progress=progress)
        except VaultError as e:
            return Outcome(True, f"{type(e).__name__}: {e}")
        return Outcome(False, f"The package was ACCEPTED and saved as {os.path.basename(out)}")

    def _ensure_bob_received_original(self, progress):
        if not self.app.replay_guard("Bob").received_before(self.app.vault.parse_container(_read(self.package))):
            self.app.receive_file("Bob", LAB_PASSWORDS["Bob"], self.package, "Alice", progress=progress)

    # -------------------------------------------------------------- scenarios
    def _scenarios(self):
        S = Scenario
        return [
            S("read", "Read the package without a key", "S1", "Storage attacker (copies the .vault)",
              "Nothing: Eve just reads the file in the shared folder",
              "AES-256-GCM confidentiality; the file key only exists wrapped for each recipient", self._read),
            S("bitflip", "Flip one bit of the encrypted content", "S2", "Storage attacker",
              "One bit of 'ciphertext' is inverted", "Ed25519 signature over the whole package (verified first)",
              lambda p: self._tamper("bitflip", lambda c: c.update(ciphertext=_flip_b64(c["ciphertext"])), p)),
            S("filename", "Change the file name in the metadata", "S3", "Storage attacker",
              "metadata.filename: payroll.txt -> payroll.exe", "Metadata is signed and authenticated as AES-GCM AAD",
              lambda p: self._tamper("filename", lambda c: c["metadata"].update(filename="payroll.exe"), p)),
            S("add_recipient", "Add Eve to the recipient list", "S3", "Storage attacker / Eve",
              "A copy of Bob's entry is added with id 'Eve'", "The recipient list is signed",
              lambda p: self._tamper("add_recipient",
                                     lambda c: c["recipients"].append(dict(c["recipients"][-1], id="Eve")), p)),
            S("remove_recipient", "Remove a recipient", "S3", "Storage attacker",
              "Alice's own entry is deleted from the recipient list", "The recipient list is signed",
              lambda p: self._tamper("remove_recipient", lambda c: c["recipients"].pop(0), p)),
            S("strip_signature", "Remove the signature", "S5", "Storage attacker",
              "The 'signature' field is deleted", "Unsigned packages are never accepted",
              lambda p: self._tamper("strip_signature", lambda c: c.pop("signature"), p)),
            S("resign", "Eve modifies the package and re-signs it with HER key", "S5", "Eve (impersonator)",
              "filename -> invoice.exe, signer_id -> Eve, new valid Ed25519 signature by Eve",
              "Bob only accepts signatures from keys he TRUSTS for Alice (trust store)", self._resign),
            S("non_recipient", "Eve (not a recipient) tries to open the package", "S4", "Eve",
              "Eve trusts Alice's public key and tries to decrypt with her own key",
              "Entries are found by key fingerprint; Eve's key is not listed", self._non_recipient),
            S("impersonate", "Eve claims to be 'Bob'", "S4", "Eve",
              "Eve uses the label 'Bob' with her own private key",
              "Access is decided by the fingerprint of the key, not by the name", self._impersonate),
            S("truncated", "Truncated / corrupted package", "S10", "Malformed-input attacker",
              "The package is cut in half", "Strict parser validates every field before using it",
              lambda p: self._bob_receives(self._save_attack("truncated", _read(self.package)[:400]), p)),
            S("replay", "Replay: deliver the same package again", "S7", "Storage attacker",
              "An exact copy of a package Bob already received is put back in the shared folder",
              "Replay cache: each user remembers the packages already accepted", self._replay),
            S("stale", "Old package signed 45 days ago", "S7", "Storage attacker",
              "A genuine package from Alice, signed 45 days ago, is delivered now",
              "Freshness window: the signed timestamp must be at most 30 days old", self._stale),
            S("revoked", "Package signed with a REVOKED key", "S13", "Thief of Alice's signing key",
              "Alice reported her key stolen and Bob revoked it; a package signed with it arrives",
              "Revoked keys are refused for old and new packages", self._revoked),
            S("substitution", "Key substitution: fake bundle named 'Alice'", "S6", "Eve (impersonator)",
              "Eve publishes a public-key bundle called 'Alice' that contains HER keys",
              "Key-change detection in the trust store (+ out-of-band fingerprint check)", self._substitution),
            S("stolen_keystore", "Stolen keystore: offline password guessing", "S11", "Device / backup thief",
              "Eve copies Bob's keystore and tries common passwords",
              "PBKDF2-HMAC-SHA256 (600,000 iterations) + AES-GCM; password policy", self._stolen_keystore),
            S("tampered_keystore", "Tampered keystore (KDF downgrade / metadata)", "S12", "Device / backup thief",
              "Iterations lowered (downgrade) or set to 10^12 (DoS); then key_id changed to 'Eve'",
              "Iteration bounds checked before deriving; whole header authenticated as AAD", self._tampered_keystore),
            S("path_traversal", "Malicious file name (path traversal)", "S14", "Malicious sender",
              "A signed package whose file name is '../../evil.txt'",
              "The output name is sanitized and written only inside Bob's inbox", self._path_traversal),
        ]

    def get(self, key: str) -> Scenario:
        return next(s for s in self.scenarios if s.key == key)

    def run(self, key: str, progress=None) -> Outcome:
        if self.app is None:
            raise VaultError("Run setup() first.")
        return self.get(key).run(progress or (lambda step: None))

    # ------------------------------------------------------- scenario bodies
    def _tamper(self, name, edit, progress) -> Outcome:
        c = self._container()
        edit(c)
        return self._bob_receives(self._save_attack(name, c), progress)

    def _read(self, progress) -> Outcome:
        raw = _read(self.package)
        header = self.app.inspect(self.package)
        found = SECRET in raw or b"Payroll" in raw
        lines = [f"Visible to anyone: file name '{header['metadata']['filename']}', "
                 f"{len(header['recipients'])} recipient(s), signer {header['signer_id'][:24]}...",
                 f"Ciphertext (first 48 chars): {header['ciphertext'][:48]}...",
                 "Plaintext found in the package: " + ("YES" if found else "NO")]
        return Outcome(not found, "Only ciphertext is stored; without a recipient's private key "
                                  "the file key cannot be unwrapped", lines)

    def _resign(self, progress) -> Outcome:
        c = self._container()
        c["metadata"]["filename"] = "invoice.exe"
        c["signer_id"] = self.app.fingerprints("Eve")["signing"]
        unsigned = {k: v for k, v in c.items() if k != "signature"}
        with self.app.keystore.unlocked_key(self.app.key_path("Eve", "signing"), LAB_PASSWORDS["Eve"]) as k:
            c["signature"] = base64.b64encode(k.sign(self.app.vault._signed_digest(unsigned))).decode()
        path = self._save_attack("resigned", c)
        eve_pub = self.app.public_key("Eve", "signing")
        self.app.vault.verify_container(_read(path), eve_pub)
        outcome = self._bob_receives(path, progress)
        outcome.details.insert(0, "Eve's signature is mathematically VALID for Eve's key...")
        outcome.details.insert(1, "...but Bob expects a file from Alice and does not trust Eve's key for Alice.")
        return outcome

    def _non_recipient(self, progress) -> Outcome:
        try:
            self.app.receive_file("Eve", LAB_PASSWORDS["Eve"], self.package, "Alice", progress=progress)
        except VaultError as e:
            return Outcome(True, f"{type(e).__name__}: {e}")
        return Outcome(False, "Eve opened the package")

    def _impersonate(self, progress) -> Outcome:
        data = _read(self.package)
        alice_sign = self.app.public_key("Alice", "signing")
        with self.app.keystore.unlocked_key(self.app.key_path("Eve", "encryption"), LAB_PASSWORDS["Eve"]) as k:
            try:
                self.app.vault.decrypt_file(data, k, "Bob", alice_sign)
            except AccessDeniedError as e:
                return Outcome(True, f"{type(e).__name__}: {e}",
                               [f"Bob's entry key_id: {self.app.fingerprints('Bob')['encryption'][:30]}...",
                                f"Eve's key:           {self.app.fingerprints('Eve')['encryption'][:30]}..."])
        return Outcome(False, "Eve decrypted the package")

    def _replay(self, progress) -> Outcome:
        self._ensure_bob_received_original(lambda s: None)
        path = self._save_attack("replayed", _read(self.package))
        return self._bob_receives(path, progress)

    def _stale(self, progress) -> Outcome:
        source = os.path.join(self.root, "old_instructions.txt")
        with open(source, "wb") as f:
            f.write(b"Old instructions: transfer the budget to account 123.")
        old = self.app.send_file("Alice", LAB_PASSWORDS["Alice"], source, ["Bob"],
                                 timestamp=int(time.time()) - 45 * DAY)
        path = self._save_attack("stale", _read(old))
        os.remove(old)
        return self._bob_receives(path, progress)

    def _revoked(self, progress) -> Outcome:
        contacts = os.path.join(self.app.user_dir("Bob"), "contacts.json")
        backup = _read(contacts)
        try:
            self.app.revoke_contact("Bob", "Alice", "signing")
            source = os.path.join(self.root, "from_thief.txt")
            with open(source, "wb") as f:
                f.write(b"Signed with the stolen key")
            sent = self.app.send_file("Alice", LAB_PASSWORDS["Alice"], source, ["Bob"])
            path = self._save_attack("revoked", _read(sent))
            os.remove(sent)
            outcome = self._bob_receives(path, progress)
        finally:
            with open(contacts, "wb") as f:             # the lab restores Bob's contacts afterwards
                f.write(backup)
        outcome.details.append("(The lab restored Bob's contacts after this scenario.)")
        return outcome

    def _substitution(self, progress) -> Outcome:
        fake = os.path.join(self.app.public_dir, "Alice_FAKE.pub.json")
        with open(fake, "wb") as f:
            f.write(export_public_bundle("Alice", self.app.public_key("Eve", "encryption"),
                                         self.app.public_key("Eve", "signing")))
        preview = self.app.preview_bundle(fake)
        lines = [f"Fake bundle signing fingerprint: {preview['signing_fingerprint'][:30]}...",
                 f"Alice's real fingerprint:        {self.app.fingerprints('Alice')['signing'][:30]}..."]
        try:
            self.app.import_contact("Bob", fake)
        except VaultError as e:
            return Outcome(True, f"{type(e).__name__}: {e}", lines)
        return Outcome(False, "Bob accepted Eve's keys as Alice's", lines)

    def _stolen_keystore(self, progress) -> Outcome:
        stolen = os.path.join(self.root, "stolen_bob_encryption.json")
        shutil.copyfile(self.app.key_path("Bob", "encryption"), stolen)
        guesses = ["123456789012", "password1234", "bob123456789", "qwerty123456", "bob passphrase"]
        lines, start = [], time.monotonic()
        for guess in guesses:
            t = time.monotonic()
            try:
                self.app.keystore.load_and_decrypt_key(stolen, guess)
                return Outcome(False, f"Password found: {guess}")
            except VaultError as e:
                lines.append(f"'{guess}': {type(e).__name__} ({(time.monotonic() - t) * 1000:.0f} ms)")
        per_guess = (time.monotonic() - start) / len(guesses)
        lines.append(f"~{per_guess * 1000:.0f} ms per guess -> 1 billion guesses would take "
                     f"~{per_guess * 1e9 / 86400 / 365:.0f} years on this computer")
        text = _read(stolen)
        lines.append("Plaintext private key inside the file: " + ("YES" if b"PRIVATE KEY" in text else "NO"))
        return Outcome(True, "No guess unlocked the key; the file holds only the encrypted key", lines)

    def _tampered_keystore(self, progress) -> Outcome:
        path = os.path.join(self.root, "tampered_bob_encryption.json")
        lines, blocked = [], True
        low = min(1000, self.min_iterations - 1)
        edits = [(f"iterations lowered to {low:,}", lambda d: d["kdf_parameters"].update(iterations=low)),
                 ("iterations set to 10^12 (DoS)", lambda d: d["kdf_parameters"].update(iterations=10 ** 12)),
                 ("key_id changed to 'Eve'", lambda d: d["metadata"].update(key_id="Eve"))]
        for label, edit in edits:
            with open(self.app.key_path("Bob", "encryption"), encoding="utf-8") as f:
                data = json.load(f)
            edit(data)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            try:
                self.app.keystore.load_and_decrypt_key(path, LAB_PASSWORDS["Bob"])
                blocked = False
                lines.append(f"{label}: ACCEPTED")
            except VaultError as e:
                lines.append(f"{label}: {type(e).__name__} - {e}")
        return Outcome(blocked, "Every modification was rejected, even with Bob's REAL password", lines)

    def _path_traversal(self, progress) -> Outcome:
        source = os.path.join(self.root, "evil.txt")
        with open(source, "wb") as f:
            f.write(b"I tried to escape the inbox")
        sent = self.app.send_file("Alice", LAB_PASSWORDS["Alice"], source, ["Bob"], filename="../../evil.txt")
        out = self.app.receive_file("Bob", LAB_PASSWORDS["Bob"], sent, "Alice", progress=progress)
        inbox = os.path.realpath(self.app.inbox_dir("Bob"))
        inside = os.path.realpath(out).startswith(inbox + os.sep)
        return Outcome(inside, f"Saved as inbox/{os.path.basename(out)} (inside Bob's inbox: {inside})",
                       ["Name declared in the package: ../../evil.txt"])
