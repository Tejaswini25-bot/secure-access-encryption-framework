
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet

from security.database import create_database, add_user
from security.mfa import generate_mfa_secret
from security.passwords import hash_password
from security.secret_storage import decrypt_secret
from security.mfa_enrollment import (
    begin_mfa_enrollment,
    confirm_mfa_enrollment,
)


class TestMFAEnrollment(unittest.TestCase):
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
            "security.mfa_enrollment.DATABASE_PATH",
            self.database_path,
        )
        self.auth_database_patch.start()
        self.addCleanup(self.auth_database_patch.stop)

        self.key = Fernet.generate_key().decode("ascii")
        self.key_patch = patch.dict(
            os.environ,
            {"MFA_ENCRYPTION_KEY": self.key},
        )
        self.key_patch.start()
        self.addCleanup(self.key_patch.stop)

        create_database()
        add_user("testuser", hash_password("example-password-123"))

    def test_enrollment_stores_encrypted_secret(self):
        success, message, uri = begin_mfa_enrollment("testuser")

        self.assertTrue(success, message)
        self.assertTrue(uri.startswith("otpauth://totp/"))

        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT mfa_secret_encrypted, mfa_enabled "
                "FROM users WHERE username = ?",
                ("testuser",),
            ).fetchone()

        self.assertIsNotNone(row[0])
        self.assertEqual(row[1], 0)
        self.assertNotIn("otpauth", row[0])

        decrypted = decrypt_secret(row[0])
        self.assertTrue(decrypted)

    def test_valid_code_enables_mfa(self):
        success, message, uri = begin_mfa_enrollment("testuser")
        self.assertTrue(success, message)

        with sqlite3.connect(self.database_path) as connection:
            encrypted_secret = connection.execute(
                "SELECT mfa_secret_encrypted FROM users "
                "WHERE username = ?",
                ("testuser",),
            ).fetchone()[0]

        from security.secret_storage import decrypt_secret
        secret = decrypt_secret(encrypted_secret)
        code = pyotp.TOTP(secret).now()

        success, message = confirm_mfa_enrollment("testuser", code)
        self.assertTrue(success, message)

        with sqlite3.connect(self.database_path) as connection:
            enabled = connection.execute(
                "SELECT mfa_enabled FROM users WHERE username = ?",
                ("testuser",),
            ).fetchone()[0]

        self.assertEqual(enabled, 1)

    def test_invalid_code_does_not_enable_mfa(self):
        success, message, uri = begin_mfa_enrollment("testuser")
        self.assertTrue(success, message)

        success, message = confirm_mfa_enrollment("testuser", "abc")
        self.assertFalse(success)

        with sqlite3.connect(self.database_path) as connection:
            enabled = connection.execute(
                "SELECT mfa_enabled FROM users WHERE username = ?",
                ("testuser",),
            ).fetchone()[0]

        self.assertEqual(enabled, 0)

    def test_unknown_user_cannot_enroll(self):
        success, message, uri = begin_mfa_enrollment("unknown")
        self.assertFalse(success)
        self.assertIsNone(uri)

    def test_enabled_mfa_cannot_be_enrolled_again(self):
        success, message, uri = begin_mfa_enrollment("testuser")
        self.assertTrue(success, message)

        with sqlite3.connect(self.database_path) as connection:
            encrypted_secret = connection.execute(
                "SELECT mfa_secret_encrypted FROM users "
                "WHERE username = ?",
                ("testuser",),
            ).fetchone()[0]

        secret = decrypt_secret(encrypted_secret)
        code = pyotp.TOTP(secret).now()
        success, message = confirm_mfa_enrollment("testuser", code)
        self.assertTrue(success, message)

        success, message, uri = begin_mfa_enrollment("testuser")
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
