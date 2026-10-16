
import os
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from security.secret_storage import encrypt_secret, decrypt_secret


class TestSecretStorage(unittest.TestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode("ascii")
        self.environment = patch.dict(
            os.environ,
            {"MFA_ENCRYPTION_KEY": self.key},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_encryption_and_decryption(self):
        secret = "example-totp-secret"
        encrypted = encrypt_secret(secret)

        self.assertNotEqual(encrypted, secret)
        self.assertEqual(decrypt_secret(encrypted), secret)

    def test_wrong_key_is_rejected(self):
        encrypted = encrypt_secret("example-totp-secret")
        wrong_key = Fernet.generate_key().decode("ascii")

        with patch.dict(
            os.environ,
            {"MFA_ENCRYPTION_KEY": wrong_key},
        ):
            with self.assertRaises(ValueError):
                decrypt_secret(encrypted)

    def test_empty_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_secret("")

    def test_missing_key_is_rejected(self):
        with patch.dict(os.environ):
            os.environ.pop("MFA_ENCRYPTION_KEY", None)

            with self.assertRaises(RuntimeError):
                encrypt_secret("example-totp-secret")


if __name__ == "__main__":
    unittest.main()
