import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from security.database import create_database, add_user
from security.passwords import hash_password, verify_password
from security.password_reset import (
    generate_otp,
    hash_otp,
    verify_otp,
    save_reset_otp,
    verify_reset_otp,
    reset_password,
    request_password_reset,
)


class TestPasswordReset(unittest.TestCase):

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

        self.reset_database_patch = patch(
            "security.password_reset.DATABASE_PATH",
            self.database_path,
        )
        self.reset_database_patch.start()
        self.addCleanup(self.reset_database_patch.stop)

        create_database()

        self.username = "testuser"
        self.password = "OldPassword123!"

        add_user(
            self.username,
            hash_password(self.password),
            "test@example.com",
        )

    def test_generate_six_digit_otp(self):
        otp = generate_otp()

        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    def test_otp_hashing_and_verification(self):
        otp = generate_otp()
        stored_hash = hash_otp(otp)

        self.assertTrue(verify_otp(otp, stored_hash))
        self.assertFalse(verify_otp("000000" if otp != "000000" else "000001", stored_hash))

    def test_invalid_otp_format(self):
        with self.assertRaises(ValueError):
            hash_otp("123")

    def test_save_otp_for_existing_user(self):
        otp = generate_otp()

        self.assertTrue(save_reset_otp(self.username, otp))

    def test_unknown_user_cannot_save_otp(self):
        otp = generate_otp()

        self.assertFalse(save_reset_otp("unknown", otp))

    def test_correct_otp_is_accepted_once(self):
        otp = generate_otp()
        self.assertTrue(save_reset_otp(self.username, otp))

        self.assertTrue(verify_reset_otp(self.username, otp))
        self.assertFalse(verify_reset_otp(self.username, otp))

    def test_wrong_otp_is_rejected(self):
        otp = generate_otp()
        self.assertTrue(save_reset_otp(self.username, otp))

        wrong_otp = "000000" if otp != "000000" else "000001"

        self.assertFalse(verify_reset_otp(self.username, wrong_otp))

    def test_five_wrong_attempts_invalidate_otp(self):
        otp = generate_otp()
        self.assertTrue(save_reset_otp(self.username, otp))

        wrong_otp = "000000" if otp != "000000" else "000001"

        for _ in range(5):
            self.assertFalse(
                verify_reset_otp(self.username, wrong_otp)
            )

        self.assertFalse(verify_reset_otp(self.username, otp))

    def test_expired_otp_is_rejected(self):
        otp = generate_otp()
        self.assertTrue(save_reset_otp(self.username, otp))

        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute("""
                    UPDATE password_reset_tokens
                    SET expires_at = 0
                    WHERE username = ?
                """, (self.username,))

        self.assertFalse(verify_reset_otp(self.username, otp))

    def test_invalid_new_password_is_rejected(self):
        result = reset_password(
            self.username,
            "123456",
            "short",
        )

        self.assertFalse(result[0])

    def test_successful_password_reset(self):
        otp = generate_otp()
        self.assertTrue(save_reset_otp(self.username, otp))

        new_password = "NewSecurePassword456!"

        success, message = reset_password(
            self.username,
            otp,
            new_password,
        )

        self.assertTrue(success, message)

        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (self.username,),
            ).fetchone()

        self.assertTrue(verify_password(new_password, row[0]))
        self.assertFalse(verify_password(self.password, row[0]))

    @patch("security.password_reset.send_password_reset_email")
    def test_password_reset_email_is_requested(self, mock_send_email):
        with patch(
            "security.password_reset.generate_otp",
            return_value="123456",
        ):
            success, message = request_password_reset(self.username)

        self.assertTrue(success)
        mock_send_email.assert_called_once_with(
            "test@example.com",
            "123456",
        )

    def test_unknown_account_gets_generic_response(self):
        result = request_password_reset("unknown_user")

        self.assertTrue(result[0])
        self.assertIn("If the account exists", result[1])


if __name__ == "__main__":
    unittest.main()
