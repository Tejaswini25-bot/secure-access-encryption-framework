
import sqlite3
import time
from contextlib import closing

from security.database import DATABASE_PATH, create_database


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


class RateLimiterError(RuntimeError):
    """Raised when rate-limit status cannot be safely maintained."""


def _prepare_database():
    try:
        create_database()
    except sqlite3.Error as exc:
        raise RateLimiterError(
            "Rate-limit database is unavailable."
        ) from exc


def is_locked(username, now=None):
    """Check whether a username is currently locked."""
    if not isinstance(username, str) or not username:
        raise ValueError("A valid username is required.")

    _prepare_database()
    current_time = time.time() if now is None else now

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                row = connection.execute(
                    "SELECT locked_until FROM login_attempts "
                    "WHERE username = ?",
                    (username,),
                ).fetchone()

    except sqlite3.Error as exc:
        raise RateLimiterError(
            "Could not check login lockout status."
        ) from exc

    return row is not None and row[0] > current_time


def record_failed_attempt(username, now=None):
    """Record a failed login and enforce the lockout policy."""
    if not isinstance(username, str) or not username:
        raise ValueError("A valid username is required.")

    _prepare_database()
    current_time = time.time() if now is None else now

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                row = connection.execute(
                    "SELECT failed_attempts, locked_until "
                    "FROM login_attempts WHERE username = ?",
                    (username,),
                ).fetchone()

                if row is not None and row[1] > current_time:
                    return True

                # Start a fresh counter after an expired lockout.
                if row is not None and row[1] > 0:
                    attempts = 0
                else:
                    attempts = row[0] if row is not None else 0

                attempts += 1

                locked_until = (
                    current_time + LOCKOUT_SECONDS
                    if attempts >= MAX_FAILED_ATTEMPTS
                    else 0
                )

                connection.execute(
                    """
                    INSERT INTO login_attempts
                        (username, failed_attempts, locked_until)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        failed_attempts = excluded.failed_attempts,
                        locked_until = excluded.locked_until
                    """,
                    (username, attempts, locked_until),
                )

        return attempts >= MAX_FAILED_ATTEMPTS

    except sqlite3.Error as exc:
        raise RateLimiterError(
            "Could not record failed login attempt."
        ) from exc


def reset_failed_attempts(username):
    """Clear failed login attempts after successful authentication."""
    if not isinstance(username, str) or not username:
        raise ValueError("A valid username is required.")

    _prepare_database()

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute(
                    "DELETE FROM login_attempts WHERE username = ?",
                    (username,),
                )

        return True

    except sqlite3.Error as exc:
        raise RateLimiterError(
            "Could not reset login attempts."
        ) from exc

