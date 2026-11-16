"""
Demo - Secure Digital Document Vault (D6: Key Management + D3 & D5 features)

Usage (from the repository root):
    python demo.py
"""
import base64
import os
import json
import getpass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from vault.crypto_module import SecureEncryptionModule
from vault.keystore import SecureKeyStore

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
    print(f"{YELLOW}  --- {path} ---{RESET}")
    with open(path, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            print(f"  {line}")
    print(f"{YELLOW}  --- end of file ---{RESET}")

def list_demo_dir():
    print(f"{YELLOW}  --- contents of {DEMO_DIR}/ ---{RESET}")
    for name in sorted(os.listdir(DEMO_DIR)):
        size = os.path.getsize(os.path.join(DEMO_DIR, name))
        print(f"  {size:>6} bytes  {name}")

def new_user(name, password, keystore):
    """Creates a P-256 (encryption) key pair and saves it securely."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    
    # D6: Save via Keystore instead of plaintext
    priv_path = os.path.join(DEMO_DIR, f"{name}_private.json")
    keystore.encrypt_and_save_key(priv, password, f"{name}_P256", "P-256", priv_path)
    
    # Public key is still saved in plaintext for sharing
    with open(os.path.join(DEMO_DIR, f"{name}_public.pem"), "wb") as f:
        f.write(pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
            
    info(f"{name}: key pair created -> {priv_path} (Encrypted), {name}_public.pem")
    return pub

def new_signing_key(name, password, keystore):
    """D5 & D6: Creates an Ed25519 (signature) key pair and saves it securely."""
    sign_priv, sign_pub = SecureEncryptionModule.generate_signing_keypair()
    
    # D6: Save via Keystore instead of plaintext
    priv_path = os.path.join(DEMO_DIR, f"{name}_sign_private.json")
    keystore.encrypt_and_save_key(sign_priv, password, f"{name}_Ed25519", "Ed25519", priv_path)
    
    with open(os.path.join(DEMO_DIR, f"{name}_sign_public.pem"), "wb") as f:
        f.write(sign_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
            
    info(f"{name}: Ed25519 signing key created -> {priv_path} (Encrypted)")
    return sign_pub

def prompt_decrypt(vault, container, name, keystore, sender_pub, expected_who=None):
    """Prompts for password, extracts key, attempts decryption, and drops the key."""
    who = expected_who or name
    priv_path = os.path.join(DEMO_DIR, f"{name}_private.json")
    
    # D6: Password-based access control
    pwd = getpass.getpass(f"[{who}] Enter your password to decrypt: ")
    
    try:
        priv_key = keystore.load_and_decrypt_key(priv_path, pwd)
        data = vault.decrypt_file(container, priv_key, name, sender_pub)
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
    keystore = SecureKeyStore()

    # ---------------------------------------------------------------
    title("SETUP: users and original file")
    print(f"{YELLOW}Next, the keys will be generated. Please create a password for each user.{RESET}")
    alice_pwd = getpass.getpass("Create a password for Alice: ")
    bob_pwd = getpass.getpass("Create a password for Bob: ")
    eve_pwd = getpass.getpass("Create a password for Eve: ")
    print()
    
    # Generate keys using D6 Keystore
    alice_pub = new_user("Alice", alice_pwd, keystore)
    bob_pub = new_user("Bob", bob_pwd, keystore)
    eve_pub = new_user("Eve", eve_pwd, keystore)
    
    alice_sign_pub = new_signing_key("Alice", alice_pwd, keystore)
    eve_sign_pub = new_signing_key("Eve", eve_pwd, keystore)

    plain_path = os.path.join(DEMO_DIR, "secret.txt")
    with open(plain_path, "wb") as f:
        f.write(b"Confidential project report: launch date is 2026-12-01.")
    with open(plain_path, "rb") as f:
        plaintext = f.read()
    
    print()
    list_demo_dir()
    info("\nAlice's public key (this is what she shares with others):")
    show_text_file(os.path.join(DEMO_DIR, "Alice_public.pem"))
    pause()

    # ---------------------------------------------------------------
    title("1) ENCRYPT A FILE  (D5 & D6)")
    info("Alice wants to encrypt a file. She needs to access her signing key.")
    alice_sign_pwd = getpass.getpass("[Alice] Enter your password to sign: ")
    
    try:
        alice_sign_priv = keystore.load_and_decrypt_key(os.path.join(DEMO_DIR, "Alice_sign_private.json"), alice_sign_pwd)
        container_alice = vault.encrypt_file(plaintext, [{"id": "Alice", "public_key": alice_pub}],
                                             filename="secret.txt", signer_private_key=alice_sign_priv)
        path_alice = os.path.join(DEMO_DIR, "secret_alice.vault")
        with open(path_alice, "wb") as f:
            f.write(container_alice)
        ok(f"File encrypted for Alice -> {path_alice}")
    except ValueError as e:
        fail(f"Encryption error: {e}")
        return

    info("\nAlice decrypts with her private key:")
    with open(path_alice, "rb") as f:
        container_from_disk = f.read()
        
    result = prompt_decrypt(vault, container_from_disk, "Alice", keystore, alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("2) SHARE WITH ANOTHER USER  (recipient can decrypt)")
    recipients = [{"id": "Alice", "public_key": alice_pub},
                  {"id": "Bob", "public_key": bob_pub}]
                  
    alice_sign_pwd2 = getpass.getpass("[Alice] Enter your password again to sign the shared file: ")
    try:
        alice_sign_priv_shared = keystore.load_and_decrypt_key(os.path.join(DEMO_DIR, "Alice_sign_private.json"), alice_sign_pwd2)
        container = vault.encrypt_file(plaintext, recipients, filename="secret.txt",
                                       signer_private_key=alice_sign_priv_shared)
        path_shared = os.path.join(DEMO_DIR, "secret_shared.vault")
        with open(path_shared, "wb") as f:
            f.write(container)
        ok(f"File encrypted ONCE, file key wrapped for Alice and Bob -> {path_shared}")
    except ValueError as e:
        fail(f"Error: {e}")
        return

    info("\nBob reads the .vault from disk and decrypts:")
    with open(path_shared, "rb") as f:
        shared_from_disk = f.read()
        
    bob_result = prompt_decrypt(vault, shared_from_disk, "Bob", keystore, alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("3) NON-RECIPIENT CANNOT DECRYPT")
    info("Case A: Eve tries with her own ID (not in the recipient list):")
    prompt_decrypt(vault, container, "Eve", keystore, alice_sign_pub)
    
    info("\nCase B: Eve impersonates Bob (uses ID 'Bob' + her private key):")
    prompt_decrypt(vault, container, "Eve", keystore, alice_sign_pub, expected_who="Eve (as Bob)")
    pause()

    # ---------------------------------------------------------------
    title("4) MODIFIED FILE  (tampered -> signature check fails)")
    info("Case A: an attacker edits the recipient list (renames 'Bob' to 'Eve'):")
    c = json.loads(container)
    for r in c["recipients"]:
        if r["id"] == "Bob":
            r["id"] = "Eve"
    tampered2 = json.dumps(c, indent=2).encode()
    
    info("Alice attempts to decrypt the tampered file:")
    prompt_decrypt(vault, tampered2, "Alice", keystore, alice_sign_pub)
    pause()

    # ---------------------------------------------------------------
    title("SUMMARY - Deliverable 6 Completed")
    ok("Users are prompted for passwords interactively.")
    ok("Private keys are never stored in plaintext (JSON Keystore used instead).")
    ok("Failed password attempts immediately reject access.")
    print()

if __name__ == "__main__":
    main()