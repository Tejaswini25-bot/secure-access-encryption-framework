
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from security.authentication import login_user
from security.database import create_database, add_user
from security.passwords import hash_password


class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_users.db"

        self.db_patch = patch(
            "security.database.DATABASE_PATH",
            self.db_path,
        )
        self.db_patch.start()

        self.auth_patch = patch(
            "security.authentication.DATABASE_PATH",
            self.db_path,
        )
        self.auth_patch.start()

        create_database()
        add_user("testuser", hash_password("TestPassword123!"))

    def tearDown(self):
        self.auth_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_correct_credentials(self):
        success, message = login_user(
            "testuser", "TestPassword123!"
        )
        self.assertTrue(success)
        self.assertEqual(message, "Login successful.")

    def test_wrong_password(self):
        success, message = login_user(
            "testuser", "WrongPassword123!"
        )
        self.assertFalse(success)
        self.assertEqual(message, "Invalid username or password.")

    def test_unknown_username(self):
        success, message = login_user(
            "unknownuser", "TestPassword123!"
        )
        self.assertFalse(success)
        self.assertEqual(message, "Invalid username or password.")

    def test_non_string_credentials(self):
        success, message = login_user(123, None)
        self.assertFalse(success)
        self.assertEqual(message, "Invalid username or password.")


if __name__ == "__main__":
    unittest.main()
