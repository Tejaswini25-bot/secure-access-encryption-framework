
import unittest

import pyotp

from security.mfa import (
    generate_mfa_secret,
    get_totp_setup_uri,
    verify_totp_code,
)


class TestMFA(unittest.TestCase):

    def setUp(self):
        self.secret = generate_mfa_secret()

    def test_secret_is_generated(self):
        self.assertTrue(self.secret)
        self.assertTrue(pyotp.random_base32() != "")

    def test_setup_uri_is_generated(self):
        uri = get_totp_setup_uri("testuser", self.secret)
        self.assertTrue(uri.startswith("otpauth://totp/"))

    def test_valid_code_is_accepted(self):
        code = pyotp.TOTP(self.secret).now()
        self.assertTrue(verify_totp_code(self.secret, code))

    def test_wrong_code_is_rejected(self):
        code = pyotp.TOTP(self.secret).now()
        wrong_code = str((int(code) + 1) % 1_000_000).zfill(6)
        self.assertFalse(verify_totp_code(self.secret, wrong_code))

    def test_malformed_code_is_rejected(self):
        self.assertFalse(verify_totp_code(self.secret, "abc"))
        self.assertFalse(verify_totp_code(self.secret, "123"))

    def test_non_string_code_is_rejected(self):
        self.assertFalse(verify_totp_code(self.secret, 123456))


if __name__ == "__main__":
    unittest.main()
