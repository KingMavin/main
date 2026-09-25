import unittest
import tempfile
import os
from pathlib import Path
from devx.secret_scanner import scan_file

class TestSecretScanner(unittest.TestCase):
    def test_safe_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("Just some safe text.")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertEqual(len(errors), 0)
        
    def test_stellar_secret_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("S" + "A"*55)
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_rsa_private_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC...\n-----END RSA PRIVATE KEY-----")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_media_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".mp4", delete=False) as f:
            f.write("fake video content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: real media files are prohibited", errors)

    def test_witness_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tr", delete=False) as f:
            f.write("fake witness content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: witness values are prohibited", errors)
        
    def test_oversized_file(self):
        # We can simulate by monkeypatching stat or creating a sparse file
        pass

if __name__ == "__main__":
    unittest.main()
