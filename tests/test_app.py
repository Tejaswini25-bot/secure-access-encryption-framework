import unittest

from app import has_reached_demo_threshold, is_nonempty_username


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
        self.assertTrue(is_nonempty_username("tejaswini"))

    def test_empty_username(self):
        self.assertFalse(is_nonempty_username(""))

    def test_whitespace_username(self):
        self.assertFalse(is_nonempty_username("   "))


if __name__ == "__main__":
    unittest.main()
