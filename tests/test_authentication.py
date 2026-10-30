import os
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet

from security.database import create_database, add_user
from security.passwords import hash_password
from security.secret_storage import encrypt_secret
from security.authentication import login_user


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.database_path = Path(self.temp_dir.name) / "test_users.db"

        self.database_patch = patch(
            "security.database.DATABASE_PATH",
            self.database_path,
        )
        self.database_patch.start()
        self.addCleanup(self.database_patch.stop)

        self.auth_database_patch = patch(
            "security.authentication.DATABASE_PATH",
            self.database_path,
        )
        self.auth_database_patch.start()
        self.addCleanup(self.auth_database_patch.stop)

        self.rate_limiter_database_patch = patch(
            "security.rate_limiter.DATABASE_PATH",
            self.database_path,
        )
        self.rate_limiter_database_patch.start()
        self.addCleanup(self.rate_limiter_database_patch.stop)

        self.key = Fernet.generate_key().decode("ascii")
        self.key_patch = patch.dict(
            os.environ,
            {"MFA_ENCRYPTION_KEY": self.key},
        )
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

        create_database()
        self.password = "example-password-123"
        add_user("testuser", hash_password(self.password))

    def test_correct_credentials_without_mfa(self):
        success, message = login_user("testuser", self.password)
        self.assertTrue(success, message)

    def test_wrong_password_is_rejected(self):
        success, message = login_user("testuser", "wrong-password")
        self.assertFalse(success)

    def test_unknown_user_is_rejected(self):
        success, message = login_user("unknown", self.password)
        self.assertFalse(success)

    def test_non_string_credentials_are_rejected(self):
        success, message = login_user(None, self.password)
        self.assertFalse(success)

    def enable_mfa_for_test_user(self):
        secret = pyotp.random_base32()
        encrypted_secret = encrypt_secret(secret)

        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(
                    "UPDATE users SET mfa_secret_encrypted = ?, "
                    "mfa_enabled = 1 WHERE username = ?",
                    (encrypted_secret, "testuser"),
                )

        return secret

    def get_failed_attempts(self, username="testuser"):
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                row = connection.execute(
                    "SELECT failed_attempts FROM login_attempts "
                    "WHERE username = ?",
                    (username,),
                ).fetchone()

        return row[0] if row else 0

    def test_mfa_login_requires_code(self):
        self.enable_mfa_for_test_user()

        success, message = login_user("testuser", self.password)
        self.assertFalse(success)

    def test_mfa_login_accepts_valid_code(self):
        secret = self.enable_mfa_for_test_user()
        code = pyotp.TOTP(secret).now()

        success, message = login_user(
            "testuser",
            self.password,
            code,
        )
        self.assertTrue(success, message)

    def test_mfa_login_rejects_invalid_code(self):
        self.enable_mfa_for_test_user()

        success, message = login_user(
            "testuser",
            self.password,
            "abc",
        )
        self.assertFalse(success)

    def test_five_failed_logins_block_correct_password(self):
        for _ in range(5):
            success, _ = login_user("testuser", "wrong-password")
            self.assertFalse(success)

        success, message = login_user("testuser", self.password)

        self.assertFalse(success)
        self.assertEqual(self.get_failed_attempts(), 5)

    def test_successful_login_resets_failed_attempts(self):
        for _ in range(3):
            login_user("testuser", "wrong-password")

        self.assertEqual(self.get_failed_attempts(), 3)

        success, message = login_user("testuser", self.password)

        self.assertTrue(success, message)
        self.assertEqual(self.get_failed_attempts(), 0)

    def test_invalid_mfa_code_counts_as_failed_attempt(self):
        self.enable_mfa_for_test_user()

        success, _ = login_user(
            "testuser",
            self.password,
            "000000",
        )

        self.assertFalse(success)
        self.assertEqual(self.get_failed_attempts(), 1)

    def test_unknown_username_counts_as_failed_attempt(self):
        success, _ = login_user("unknown", self.password)

        self.assertFalse(success)
        self.assertEqual(self.get_failed_attempts("unknown"), 1)


if __name__ == "__main__":
    unittest.main()

