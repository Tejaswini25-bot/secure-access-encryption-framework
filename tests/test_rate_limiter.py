
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security.database import create_database
from security.rate_limiter import (
    is_locked,
    record_failed_attempt,
    reset_failed_attempts,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_SECONDS,
)


class TestRateLimiter(unittest.TestCase):
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

        self.limiter_patch = patch(
            "security.rate_limiter.DATABASE_PATH",
            self.database_path,
        )
        self.limiter_patch.start()
        self.addCleanup(self.limiter_patch.stop)

        create_database()

    def test_account_is_not_locked_initially(self):
        self.assertFalse(is_locked("testuser", now=1000))

    def test_lockout_starts_after_fifth_failure(self):
        for _ in range(MAX_FAILED_ATTEMPTS - 1):
            locked = record_failed_attempt("testuser", now=1000)
            self.assertFalse(locked)

        locked = record_failed_attempt("testuser", now=1000)
        self.assertTrue(locked)
        self.assertTrue(is_locked("testuser", now=1000))

    def test_lockout_expires_after_five_minutes(self):
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_attempt("testuser", now=1000)

        self.assertTrue(is_locked("testuser", now=1000))
        self.assertFalse(
            is_locked("testuser", now=1000 + LOCKOUT_SECONDS + 1)
        )

    def test_locked_attempt_does_not_increase_counter(self):
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_attempt("testuser", now=1000)

        record_failed_attempt("testuser", now=1010)

        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT failed_attempts FROM login_attempts "
                "WHERE username = ?",
                ("testuser",),
            ).fetchone()

        self.assertEqual(row[0], MAX_FAILED_ATTEMPTS)

    def test_reset_clears_failed_attempts(self):
        record_failed_attempt("testuser", now=1000)
        self.assertTrue(reset_failed_attempts("testuser"))

        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT username FROM login_attempts WHERE username = ?",
                ("testuser",),
            ).fetchone()

        self.assertIsNone(row)
        self.assertFalse(is_locked("testuser", now=1000))

    def test_different_users_have_separate_counters(self):
        record_failed_attempt("alice", now=1000)
        record_failed_attempt("bob", now=1000)

        with closing(sqlite3.connect(self.database_path)) as connection:
            rows = connection.execute(
                "SELECT username, failed_attempts FROM login_attempts "
                "ORDER BY username"
            ).fetchall()

        self.assertEqual(
            rows,
            [("alice", 1), ("bob", 1)],
        )


if __name__ == "__main__":
    unittest.main()

