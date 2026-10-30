import sqlite3
from contextlib import closing

from security.database import DATABASE_PATH, create_database
from security.passwords import verify_password
from security.secret_storage import decrypt_secret
from security.mfa import verify_totp_code
from security.rate_limiter import (
    RateLimiterError,
    is_locked,
    record_failed_attempt,
    reset_failed_attempts,
)


def login_user(username, password, mfa_code=None):
    if (
        not isinstance(username, str)
        or not username
        or not isinstance(password, str)
    ):
        return False, "Invalid username or password."

    try:
        if is_locked(username):
            return False, "Login temporarily unavailable. Try again later."

        create_database()

        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                row = connection.execute(
                    """
                    SELECT password_hash, mfa_secret_encrypted, mfa_enabled
                    FROM users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()

    except (sqlite3.Error, RateLimiterError):
        return False, "Login could not be completed."

    if row is None:
        try:
            record_failed_attempt(username)
        except RateLimiterError:
            return False, "Login could not be completed."

        return False, "Invalid username or password."

    password_hash, encrypted_secret, mfa_enabled = row

    if not verify_password(password, password_hash):
        try:
            record_failed_attempt(username)
        except RateLimiterError:
            return False, "Login could not be completed."

        return False, "Invalid username or password."

    if mfa_enabled == 1:
        if not isinstance(mfa_code, str):
            try:
                record_failed_attempt(username)
            except RateLimiterError:
                return False, "Login could not be completed."

            return False, "Invalid username or password."

        if not encrypted_secret:
            return False, "MFA verification could not be completed."

        try:
            secret = decrypt_secret(encrypted_secret)
        except (RuntimeError, ValueError):
            return False, "MFA verification could not be completed."

        if not verify_totp_code(secret, mfa_code):
            try:
                record_failed_attempt(username)
            except RateLimiterError:
                return False, "Login could not be completed."

            return False, "Invalid username or password."

    try:
        reset_failed_attempts(username)
    except RateLimiterError:
        return False, "Login could not be completed."

    return True, "Login successful."
