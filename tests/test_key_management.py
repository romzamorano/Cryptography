import unittest
import os
import json
import shutil
import tempfile
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from vault.keystore import SecureKeyStore

class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        # Initialize the keystore engine
        self.keystore = SecureKeyStore()
        
        # Reduce iterations ONLY for fast test execution (in production it must be 600,000)
        self.keystore.iterations = 1000 
        
        # Create a temporary directory to avoid cluttering the repository with test files
        self.test_dir = tempfile.mkdtemp()
        self.key_path = os.path.join(self.test_dir, "test_keystore.json")
        self.backup_path = os.path.join(self.test_dir, "backup_keystore.json")
        
        # Test data setup
        self.password = "SuperSecretPassword123!"
        self.wrong_password = "WrongPassword456!"
        self.key_id = "Alice_P256"
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def tearDown(self):
        # Clean up temporary files after testing is complete
        shutil.rmtree(self.test_dir)

    def test_1_correct_password_access_granted(self):
        """Test: Correct password -> access granted"""
        # Encrypt and save the private key
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path
        )
        
        # Attempt to recover it using the correct password
        recovered_key = self.keystore.load_and_decrypt_key(self.key_path, self.password)
        
        # Verify that the recovered key is mathematically identical to the original one
        self.assertEqual(
            self.private_key.private_numbers().private_value,
            recovered_key.private_numbers().private_value
        )

    def test_2_wrong_password_access_denied(self):
        """Test: Wrong password -> access denied"""
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path
        )
        
        # Attempt to recover it with the WRONG password; it must raise a ValueError
        with self.assertRaises(ValueError) as context:
            self.keystore.load_and_decrypt_key(self.key_path, self.wrong_password)
            
        # Ensure the exception message matches the security failure
        self.assertIn("Incorrect password or tampered Keystore", str(context.exception))

    def test_3_modified_keystore_failure(self):
        """Test: Modified keystore -> failure (Tampering / Integrity check)"""
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path
        )
        
        # Simulate an attacker modifying a single bit in the JSON file
        with open(self.key_path, 'r') as f:
            data = json.load(f)
            
        # Modify the ciphertext (change the last character of the base64 string)
        ct_list = list(data["encrypted_private_key"])
        ct_list[-1] = 'A' if ct_list[-1] != 'A' else 'B'
        data["encrypted_private_key"] = "".join(ct_list)
        
        with open(self.key_path, 'w') as f:
            json.dump(data, f)
            
        # The system must detect the modification via the AES-GCM tag and reject it
        with self.assertRaises(ValueError):
            self.keystore.load_and_decrypt_key(self.key_path, self.password)

    def test_4_backup_restore_works(self):
        """Test: Backup -> restore works"""
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path
        )
        
        # Make a physical backup of the file (simulating an OS-level copy and paste)
        shutil.copy2(self.key_path, self.backup_path)
        
        # Delete the original file, simulating computer damage or formatting
        os.remove(self.key_path)
        
        # Restore the key from the backup using the password
        recovered_key = self.keystore.load_and_decrypt_key(self.backup_path, self.password)
        
        self.assertIsNotNone(recovered_key)
        self.assertEqual(
            self.private_key.private_numbers().private_value,
            recovered_key.private_numbers().private_value
        )

    def test_5_stolen_keystore_alone_cannot_decrypt(self):
        """Test: Stolen keystore alone -> cannot decrypt"""
        # An attacker steals the JSON file but DOES NOT have the password.
        # We demonstrate that without the password, the Key Derivation Function (KDF) 
        # will generate an incorrect encryption key, causing decryption to fail.
        self.keystore.encrypt_and_save_key(
            self.private_key, self.password, self.key_id, "P-256", self.key_path
        )
        
        # The attacker attempts to guess passwords (simulating a failed brute-force attack)
        attacker_guesses = ["password", "123456", "admin", "Alice123"]
        
        for guess in attacker_guesses:
            with self.assertRaises(ValueError):
                self.keystore.load_and_decrypt_key(self.key_path, guess)

if __name__ == '__main__':
    unittest.main()