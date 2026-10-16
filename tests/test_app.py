import unittest

from app import has_reached_demo_threshold, is_valid_username


class TestProjectHelpers(unittest.TestCase):

    def test_threshold_below_limit(self):
        self.assertFalse(has_reached_demo_threshold(3))

    def test_threshold_at_limit(self):
        self.assertTrue(has_reached_demo_threshold(5))

    def test_threshold_custom_limit(self):
        self.assertFalse(
            has_reached_demo_threshold(7, threshold=10)
        )

    def test_valid_username(self):
        self.assertTrue(is_valid_username("tejaswini"))

    def test_valid_username_with_allowed_symbols(self):
        self.assertTrue(is_valid_username("tejaswini_25"))

    def test_empty_username(self):
        self.assertFalse(is_valid_username(""))

    def test_whitespace_username(self):
        self.assertFalse(is_valid_username("   "))

    def test_username_too_short(self):
        self.assertFalse(is_valid_username("ab"))

    def test_username_too_long(self):
        self.assertFalse(is_valid_username("a" * 33))

    def test_username_with_invalid_characters(self):
        self.assertFalse(is_valid_username("tejaswini!!!"))

    def test_username_starting_with_symbol(self):
        self.assertFalse(is_valid_username("_tejaswini"))

    def test_username_with_surrounding_spaces(self):
        self.assertFalse(is_valid_username(" tejaswini "))

    def test_non_string_username(self):
        self.assertFalse(is_valid_username(123))


if __name__ == "__main__":
    unittest.main()
