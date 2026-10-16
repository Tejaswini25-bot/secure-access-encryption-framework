
import unittest

from security.passwords import hash_password, verify_password


class TestPasswordSecurity(unittest.TestCase):

    def test_password_hash_is_created(self):
        hashed = hash_password("DemoPassword123!")
        self.assertTrue(hashed.startswith("$argon2id$"))

    def test_correct_password_is_accepted(self):
        hashed = hash_password("DemoPassword123!")
        self.assertTrue(
            verify_password("DemoPassword123!", hashed)
        )

    def test_wrong_password_is_rejected(self):
        hashed = hash_password("DemoPassword123!")
        self.assertFalse(
            verify_password("WrongPassword123!", hashed)
        )

    def test_empty_password_is_rejected(self):
        with self.assertRaises(ValueError):
            hash_password("")

    def test_non_string_password_is_rejected(self):
        with self.assertRaises(ValueError):
            hash_password(123)

    def test_non_string_verification_input_is_rejected(self):
        self.assertFalse(verify_password(123, "some-hash"))


if __name__ == "__main__":
    unittest.main()
