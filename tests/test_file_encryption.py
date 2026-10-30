
import tempfile
import unittest
from pathlib import Path

from security.file_encryption import encrypt_file, decrypt_file


class TestFileEncryption(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        self.original_file = self.test_dir / "original.txt"
        self.encrypted_file = self.test_dir / "original.enc"
        self.decrypted_file = self.test_dir / "decrypted.txt"

        self.password = "StrongTestPassword123!"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypt_and_decrypt_file(self):
        original_content = b"This is a secret message."
        self.original_file.write_bytes(original_content)

        encrypt_file(
            self.original_file,
            self.encrypted_file,
            self.password,
        )

        self.assertTrue(self.encrypted_file.exists())
        self.assertNotEqual(
            self.original_file.read_bytes(),
            self.encrypted_file.read_bytes(),
        )

        decrypt_file(
            self.encrypted_file,
            self.decrypted_file,
            self.password,
        )

        self.assertEqual(
            self.decrypted_file.read_bytes(),
            original_content,
        )

    def test_wrong_password_is_rejected(self):
        self.original_file.write_text("Secret information")

        encrypt_file(
            self.original_file,
            self.encrypted_file,
            self.password,
        )

        with self.assertRaises(ValueError):
            decrypt_file(
                self.encrypted_file,
                self.decrypted_file,
                "WrongPassword123!",
            )

        self.assertFalse(self.decrypted_file.exists())

    def test_tampered_file_is_rejected(self):
        self.original_file.write_text("Secret information")

        encrypt_file(
            self.original_file,
            self.encrypted_file,
            self.password,
        )

        encrypted_data = bytearray(
            self.encrypted_file.read_bytes()
        )

        encrypted_data[-1] ^= 1
        self.encrypted_file.write_bytes(encrypted_data)

        with self.assertRaises(ValueError):
            decrypt_file(
                self.encrypted_file,
                self.decrypted_file,
                self.password,
            )

        self.assertFalse(self.decrypted_file.exists())

    def test_existing_output_file_is_not_overwritten(self):
        self.original_file.write_text("Secret information")
        self.encrypted_file.write_text("Existing content")

        with self.assertRaises(FileExistsError):
            encrypt_file(
                self.original_file,
                self.encrypted_file,
                self.password,
            )

        self.assertEqual(
            self.encrypted_file.read_text(),
            "Existing content",
        )

    def test_missing_input_file_is_rejected(self):
        missing_file = self.test_dir / "missing.txt"

        with self.assertRaises(FileNotFoundError):
            encrypt_file(
                missing_file,
                self.encrypted_file,
                self.password,
            )

    def test_empty_file_can_be_encrypted_and_decrypted(self):
        self.original_file.write_bytes(b"")

        encrypt_file(
            self.original_file,
            self.encrypted_file,
            self.password,
        )

        decrypt_file(
            self.encrypted_file,
            self.decrypted_file,
            self.password,
        )

        self.assertEqual(
            self.decrypted_file.read_bytes(),
            b"",
        )


if __name__ == "__main__":
    unittest.main()
