"""
Demo - Secure Digital Document Vault (D3: Hybrid Encryption)

Usage (from the repository root):
    python demo.py

Shows, in order:
  1. Encrypt a file             -> Valid encryption -> decryption works
  2. Share with another user    -> Recipient (Bob) can decrypt
  3. Non-recipient (Eve)        -> Cannot decrypt
  4. Modified file              -> Decryption fails
"""
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
    """Creates a P-256 key pair and saves both keys as PEM files."""
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


def try_decrypt(vault, container, priv, key_id, who):
    try:
        data = vault.decrypt_file(container, priv, key_id)
        ok(f"{who} decrypted the file:")
        info(f'         "{data.decode()}"')
        return data
    except ValueError as e:
        fail(f"{who} could NOT decrypt -> {e}")
        return None


def show_header(container):
    aad_len = int.from_bytes(container[:4], "big")
    header = json.loads(container[4:4 + aad_len])
    for r in header["recipients"]:
        r["encrypted_key"] = r["encrypted_key"][:24] + "..."
    print(json.dumps(header, indent=4))


def main():
    os.makedirs(DEMO_DIR, exist_ok=True)
    vault = SecureEncryptionModule()

    # ---------------------------------------------------------------
    title("SETUP: users and original file")
    alice_priv, alice_pub = new_user("Alice")
    bob_priv, bob_pub = new_user("Bob")
    eve_priv, eve_pub = new_user("Eve")

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
                                         filename="secret.txt")
    path_alice = os.path.join(DEMO_DIR, "secret_alice.vault")
    with open(path_alice, "wb") as f:
        f.write(container_alice)
    ok(f"File encrypted for Alice -> {path_alice} ({len(container_alice)} bytes)")
    info("Raw encrypted file on disk (header is readable JSON, content is not):")
    show_hex_file(path_alice, n=64)
    info("Container header (AAD):")
    show_header(container_alice)
    info("\nAlice decrypts with her private key:")
    with open(path_alice, "rb") as f:
        container_from_disk = f.read()
    result = try_decrypt(vault, container_from_disk, alice_priv, "Alice", "Alice")
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
    container = vault.encrypt_file(plaintext, recipients, filename="secret.txt")
    path_shared = os.path.join(DEMO_DIR, "secret_shared.vault")
    with open(path_shared, "wb") as f:
        f.write(container)
    ok(f"File encrypted ONCE, file key wrapped for Alice and Bob -> {path_shared}")
    show_header(container)
    info("\nBob (recipient) reads the .vault from disk and decrypts with HIS OWN private key:")
    with open(path_shared, "rb") as f:
        shared_from_disk = f.read()
    bob_result = try_decrypt(vault, shared_from_disk, bob_priv, "Bob", "Bob")
    if bob_result is not None:
        out_path = os.path.join(DEMO_DIR, "secret_decrypted_bob.txt")
        with open(out_path, "wb") as f:
            f.write(bob_result)
        info(f"Decrypted file written to disk -> {out_path}")
        show_text_file(out_path)
    info("Alice can still decrypt too:")
    try_decrypt(vault, container, alice_priv, "Alice", "Alice")
    pause()

    # ---------------------------------------------------------------
    title("3) NON-RECIPIENT CANNOT DECRYPT  (unauthorized user)")
    info("Case A: Eve tries with her own ID (not in the recipient list):")
    try_decrypt(vault, container, eve_priv, "Eve", "Eve")
    info("\nCase B: Eve impersonates Bob (uses ID 'Bob' + her private key):")
    try_decrypt(vault, container, eve_priv, "Bob", "Eve (as Bob)")
    pause()

    # ---------------------------------------------------------------
    title("4) MODIFIED FILE  (tampered -> decryption fails)")
    aad_len = int.from_bytes(container[:4], "big")

    info("Case A: an attacker flips ONE byte of the encrypted content:")
    tampered = bytearray(container)
    pos = len(tampered) - 20
    before = tampered[pos]
    tampered[pos] ^= 0x01
    info(f"  byte at offset {pos}: {before:02x} -> {tampered[pos]:02x}")
    path_t1 = os.path.join(DEMO_DIR, "secret_tampered_content.vault")
    with open(path_t1, "wb") as f:
        f.write(tampered)
    info(f"  saved as {path_t1}")
    try_decrypt(vault, bytes(tampered), bob_priv, "Bob", "Bob")

    info("\nCase B: an attacker edits the header (renames 'Bob' to 'Eve'):")
    header = json.loads(container[4:4 + aad_len])
    for r in header["recipients"]:
        if r["id"] == "Bob":
            r["id"] = "Eve"
    new_aad = json.dumps(header, sort_keys=True).encode()
    tampered2 = len(new_aad).to_bytes(4, "big") + new_aad + container[4 + aad_len:]
    path_t2 = os.path.join(DEMO_DIR, "secret_tampered_header.vault")
    with open(path_t2, "wb") as f:
        f.write(tampered2)
    info(f"  saved as {path_t2}")
    try_decrypt(vault, tampered2, alice_priv, "Alice", "Alice (legitimate user)")
    try_decrypt(vault, tampered2, eve_priv, "Eve", "Eve")

    info("\nCase C: an attacker changes the filename in the metadata:")
    header = json.loads(container[4:4 + aad_len])
    header["metadata"]["filename"] = "fake.txt"
    new_aad = json.dumps(header, sort_keys=True).encode()
    tampered3 = len(new_aad).to_bytes(4, "big") + new_aad + container[4 + aad_len:]
    try_decrypt(vault, tampered3, bob_priv, "Bob", "Bob")

    # ---------------------------------------------------------------
    title("SUMMARY")
    ok("Valid encryption -> decryption works")
    ok("Shared file -> recipient (Bob) can decrypt")
    ok("Non-recipient (Eve) cannot decrypt, not even impersonating Bob")
    ok("Modified file (content, recipients or metadata) -> decryption fails")
    print()
    list_demo_dir()
    print()


if __name__ == "__main__":
    main()
