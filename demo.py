"""
Demo - Secure Digital Document Vault (D3: Hybrid Encryption + D5: Digital Signatures)

Usage (from the repository root):
    python demo.py

Shows, in order:
  1. Encrypt a file             -> Valid encryption -> decryption works
  2. Share with another user    -> Recipient (Bob) can decrypt
  3. Non-recipient (Eve)        -> Cannot decrypt
  4. Modified file              -> Signature check fails, file rejected
  5. Digital signatures (D5)    -> Wrong key / forged / unsigned -> rejected
"""
import base64
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from vault.crypto_module import SecureEncryptionModule

DEMO_DIR = "demo_files"

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def title(text):
    print(f"\n{BOLD}{CYAN}{'=' * 64}\n  {text}\n{'=' * 64}{RESET}")


def ok(text):
    print(f"{GREEN}  [OK]   {text}{RESET}")


def fail(text):
    print(f"{RED}  [FAIL] {text}{RESET}")


def info(text):
    print(f"  {text}")


def pause():
    input(f"\n{YELLOW}  Press Enter to continue...{RESET}")


def show_text_file(path):
    """Prints a text file read from disk, like 'type' / 'cat'."""
    print(f"{YELLOW}  --- {path} ---{RESET}")
    with open(path, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            print(f"  {line}")
    print(f"{YELLOW}  --- end of file ---{RESET}")


def show_hex_file(path, n=96):
    """Prints the first n bytes of a binary file as a hex dump."""
    with open(path, "rb") as f:
        data = f.read()
    print(f"{YELLOW}  --- {path} ({len(data)} bytes, first {min(n, len(data))} shown) ---{RESET}")
    for i in range(0, min(n, len(data)), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hexs:<48}  {text}")
    print(f"{YELLOW}  --- ... last 48 bytes (encrypted content + GCM tag) ---{RESET}")
    start = max(len(data) - 48, 0)
    for i in range(start, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hexs:<48}  {text}")
    print(f"{YELLOW}  --- end ---{RESET}")


def list_demo_dir():
    """Lists the files in demo_files/, like 'dir' / 'ls -l'."""
    print(f"{YELLOW}  --- contents of {DEMO_DIR}/ ---{RESET}")
    for name in sorted(os.listdir(DEMO_DIR)):
        size = os.path.getsize(os.path.join(DEMO_DIR, name))
        print(f"  {size:>6} bytes  {name}")


def new_user(name):
    """Creates a P-256 (encryption) key pair and saves both keys as PEM files."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    with open(os.path.join(DEMO_DIR, f"{name}_private.pem"), "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(os.path.join(DEMO_DIR, f"{name}_public.pem"), "wb") as f:
        f.write(pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    info(f"{name}: key pair created -> {DEMO_DIR}/{name}_private.pem, {name}_public.pem")
    return priv, pub


def new_signing_key(name):
    """D5: Creates an Ed25519 (signature) key pair and saves both keys as PEM files."""
    sign_priv, sign_pub = SecureEncryptionModule.generate_signing_keypair()
    with open(os.path.join(DEMO_DIR, f"{name}_sign_private.pem"), "wb") as f:
        f.write(sign_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(os.path.join(DEMO_DIR, f"{name}_sign_public.pem"), "wb") as f:
        f.write(sign_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    info(f"{name}: Ed25519 signing key -> {SecureEncryptionModule.key_fingerprint(sign_pub)}")
    return sign_priv, sign_pub


def try_decrypt(vault, container, priv, key_id, who, sender_pub):
    try:
        data = vault.decrypt_file(container, priv, key_id, sender_pub)
        ok(f"{who} decrypted the file:")
        info(f'         "{data.decode()}"')
        return data
    except ValueError as e:
        fail(f"{who} could NOT decrypt -> {e}")
        return None


def show_header(container):
    header = json.loads(container)
    for r in header["recipients"]:
        r["encrypted_key"] = r["encrypted_key"][:24] + "..."
    for field in ("ciphertext", "signature"):
        header[field] = header[field][:24] + "..."
    print(json.dumps(header, indent=4))


def flip_b64(value):
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def main():
    os.makedirs(DEMO_DIR, exist_ok=True)
    vault = SecureEncryptionModule()

    # ---------------------------------------------------------------
    title("SETUP: users and original file")
    alice_priv, alice_pub = new_user("Alice")
    bob_priv, bob_pub = new_user("Bob")
    eve_priv, eve_pub = new_user("Eve")
    alice_sign_priv, alice_sign_pub = new_signing_key("Alice")
    eve_sign_priv, eve_sign_pub = new_signing_key("Eve")

    plain_path = os.path.join(DEMO_DIR, "secret.txt")
    with open(plain_path, "wb") as f:
        f.write(b"Confidential project report: launch date is 2026-12-01.")
    with open(plain_path, "rb") as f:
        plaintext = f.read()
    print()
    list_demo_dir()
    info("\nAlice's public key (this is what she shares with others):")
    show_text_file(os.path.join(DEMO_DIR, "Alice_public.pem"))
    info("\nOriginal file (readable plaintext):")
    show_text_file(plain_path)
    pause()

    # ---------------------------------------------------------------
    title("1) ENCRYPT A FILE  (valid encryption -> decryption works)")
    container_alice = vault.encrypt_file(plaintext, [{"id": "Alice", "public_key": alice_pub}],
                                         filename="secret.txt", signer_private_key=alice_sign_priv)
    path_alice = os.path.join(DEMO_DIR, "secret_alice.vault")
    with open(path_alice, "wb") as f:
        f.write(container_alice)
    ok(f"File encrypted for Alice -> {path_alice} ({len(container_alice)} bytes)")
    info("Signed container (metadata is readable JSON, content is not):")
    show_header(container_alice)
    info("\nAlice decrypts with her private key:")
    with open(path_alice, "rb") as f:
        container_from_disk = f.read()
    result = try_decrypt(vault, container_from_disk, alice_priv, "Alice", "Alice", alice_sign_pub)
    if result is not None:
        out_path = os.path.join(DEMO_DIR, "secret_decrypted_alice.txt")
        with open(out_path, "wb") as f:
            f.write(result)
        info(f"Decrypted file written to disk -> {out_path}")
        show_text_file(out_path)
    if result == plaintext:
        ok("Decrypted content is IDENTICAL to the original file")
    pause()

    # ---------------------------------------------------------------
    title("2) SHARE WITH ANOTHER USER  (recipient can decrypt)")
    recipients = [{"id": "Alice", "public_key": alice_pub},
                  {"id": "Bob", "public_key": bob_pub}]
    container = vault.encrypt_file(plaintext, recipients, filename="secret.txt",
                                   signer_private_key=alice_sign_priv)
    path_shared = os.path.join(DEMO_DIR, "secret_shared.vault")
    with open(path_shared, "wb") as f:
        f.write(container)
    ok(f"File encrypted ONCE, file key wrapped for Alice and Bob -> {path_shared}")
    show_header(container)
    info("\nBob (recipient) reads the .vault from disk and decrypts with HIS OWN private key:")
    with open(path_shared, "rb") as f:
        shared_from_disk = f.read()
    bob_result = try_decrypt(vault, shared_from_disk, bob_priv, "Bob", "Bob", alice_sign_pub)
    if bob_result is not None:
        out_path = os.path.join(DEMO_DIR, "secret_decrypted_bob.txt")
        with open(out_path, "wb") as f:
            f.write(bob_result)
        info(f"Decrypted file written to disk -> {out_path}")
        show_text_file(out_path)
    info("Alice can still decrypt too:")
    try_decrypt(vault, container, alice_priv, "Alice", "Alice", alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("3) NON-RECIPIENT CANNOT DECRYPT  (unauthorized user)")
    info("Case A: Eve tries with her own ID (not in the recipient list):")
    try_decrypt(vault, container, eve_priv, "Eve", "Eve", alice_sign_pub)
    info("\nCase B: Eve impersonates Bob (uses ID 'Bob' + her private key):")
    try_decrypt(vault, container, eve_priv, "Bob", "Eve (as Bob)", alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("4) MODIFIED FILE  (tampered -> signature check fails)")

    info("Case A: an attacker flips ONE bit of the encrypted content:")
    c = json.loads(container)
    c["ciphertext"] = flip_b64(c["ciphertext"])
    tampered = json.dumps(c, indent=2).encode()
    path_t1 = os.path.join(DEMO_DIR, "secret_tampered_content.vault")
    with open(path_t1, "wb") as f:
        f.write(tampered)
    info(f"  saved as {path_t1}")
    try_decrypt(vault, tampered, bob_priv, "Bob", "Bob", alice_sign_pub)

    info("\nCase B: an attacker edits the recipient list (renames 'Bob' to 'Eve'):")
    c = json.loads(container)
    for r in c["recipients"]:
        if r["id"] == "Bob":
            r["id"] = "Eve"
    tampered2 = json.dumps(c, indent=2).encode()
    path_t2 = os.path.join(DEMO_DIR, "secret_tampered_header.vault")
    with open(path_t2, "wb") as f:
        f.write(tampered2)
    info(f"  saved as {path_t2}")
    try_decrypt(vault, tampered2, alice_priv, "Alice", "Alice (legitimate user)", alice_sign_pub)
    try_decrypt(vault, tampered2, eve_priv, "Eve", "Eve", alice_sign_pub)

    info("\nCase C: an attacker changes the filename in the metadata:")
    c = json.loads(container)
    c["metadata"]["filename"] = "fake.txt"
    try_decrypt(vault, json.dumps(c).encode(), bob_priv, "Bob", "Bob", alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("5) DIGITAL SIGNATURES  (origin authentication, D5)")
    info("Case A: Bob verifies who created the file:")
    try:
        vault.verify_container(container, alice_sign_pub)
        ok(f"Valid signature from {SecureEncryptionModule.key_fingerprint(alice_sign_pub)}")
    except ValueError as e:
        fail(str(e))

    info("\nCase B: Bob verifies with the WRONG public key (Eve's):")
    try_decrypt(vault, container, bob_priv, "Bob", "Bob", eve_sign_pub)

    info("\nCase C: Eve modifies the file and RE-SIGNS it with her own key:")
    c = json.loads(container)
    c["metadata"]["filename"] = "malware.exe"
    c["signer_id"] = SecureEncryptionModule.key_fingerprint(eve_sign_pub)
    unsigned = {k: v for k, v in c.items() if k != "signature"}
    c["signature"] = base64.b64encode(eve_sign_priv.sign(vault._signed_digest(unsigned))).decode()
    forged = json.dumps(c, indent=2).encode()
    path_t3 = os.path.join(DEMO_DIR, "secret_forged.vault")
    with open(path_t3, "wb") as f:
        f.write(forged)
    info(f"  saved as {path_t3}")
    try_decrypt(vault, forged, bob_priv, "Bob", "Bob (expects Alice)", alice_sign_pub)

    info("\nCase D: an attacker REMOVES the signature:")
    c = json.loads(container)
    del c["signature"]
    try_decrypt(vault, json.dumps(c).encode(), bob_priv, "Bob", "Bob", alice_sign_pub)

    # ---------------------------------------------------------------
    title("SUMMARY")
    ok("Valid encryption + valid signature -> decryption works")
    ok("Shared file -> recipient (Bob) can decrypt")
    ok("Non-recipient (Eve) cannot decrypt, not even impersonating Bob")
    ok("Modified file (content, recipients or metadata) -> rejected")
    ok("Wrong public key, forged signature or removed signature -> rejected")
    print()
    list_demo_dir()
    print()


if __name__ == "__main__":
    main()
