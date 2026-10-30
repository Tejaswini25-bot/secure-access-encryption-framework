import secrets
import sqlite3
import time
from contextlib import closing

from security.database import DATABASE_PATH, create_database
from security.email_service import send_password_reset_email
from security.passwords import hash_password, verify_password


OTP_EXPIRY_SECONDS = 300
MAX_OTP_ATTEMPTS = 5


def generate_otp():
    """Generate a cryptographically secure six-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp):
    """Securely hash an OTP using Argon2."""
    if not isinstance(otp, str) or len(otp) != 6 or not otp.isdigit():
        raise ValueError("OTP must contain exactly six digits.")

    return hash_password(otp)


def verify_otp(otp, stored_hash):
    """Verify an OTP against its Argon2 hash."""
    if not isinstance(otp, str) or not isinstance(stored_hash, str):
        return False

    if len(otp) != 6 or not otp.isdigit():
        return False

    return verify_password(otp, stored_hash)


def get_otp_expiry():
    """Return the OTP expiration timestamp."""
    return time.time() + OTP_EXPIRY_SECONDS


def save_reset_otp(username, otp):
    """Save a hashed OTP for an existing user."""
    if not isinstance(username, str) or not username:
        return False

    try:
        otp_hash = hash_otp(otp)
    except ValueError:
        return False

    create_database()

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        with connection:
            user = connection.execute(
                "SELECT username FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user is None:
                return False

            connection.execute("""
                INSERT OR REPLACE INTO password_reset_tokens
                (username, otp_hash, expires_at, attempts)
                VALUES (?, ?, ?, 0)
            """, (username, otp_hash, get_otp_expiry()))

    return True


def verify_reset_otp(username, otp):
    """Verify an OTP, enforce expiry and attempts, and consume it."""
    if not isinstance(username, str) or not username:
        return False

    create_database()

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        with connection:
            record = connection.execute("""
                SELECT otp_hash, expires_at, attempts
                FROM password_reset_tokens
                WHERE username = ?
            """, (username,)).fetchone()

            if record is None:
                return False

            stored_hash, expires_at, attempts = record

            if time.time() >= expires_at or attempts >= MAX_OTP_ATTEMPTS:
                connection.execute(
                    "DELETE FROM password_reset_tokens WHERE username = ?",
                    (username,),
                )
                return False

            if not verify_otp(otp, stored_hash):
                new_attempts = attempts + 1

                if new_attempts >= MAX_OTP_ATTEMPTS:
                    connection.execute(
                        "DELETE FROM password_reset_tokens WHERE username = ?",
                        (username,),
                    )
                else:
                    connection.execute("""
                        UPDATE password_reset_tokens
                        SET attempts = ?
                        WHERE username = ?
                    """, (new_attempts, username))

                return False

            connection.execute(
                "DELETE FROM password_reset_tokens WHERE username = ?",
                (username,),
            )

            return True


def request_password_reset(username):
    """Generate and email a reset OTP without revealing account existence."""
    generic_message = (
        "If the account exists and has an email address, "
        "a reset code will be sent."
    )

    if not isinstance(username, str) or not username:
        return True, generic_message

    create_database()

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        user = connection.execute(
            "SELECT email FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not user[0]:
        return True, generic_message

    otp = generate_otp()

    if not save_reset_otp(username, otp):
        return True, generic_message

    try:
        send_password_reset_email(user[0], otp)
    except Exception:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute(
                    "DELETE FROM password_reset_tokens WHERE username = ?",
                    (username,),
                )
        raise

    return True, generic_message

def reset_password(username, otp, new_password):
    """Reset a user's password after valid OTP verification."""

    if not isinstance(new_password, str) or len(new_password) < 12:
        return False, "Password must contain at least 12 characters."

    if not verify_reset_otp(username, otp):
        return False, "Invalid or expired verification code."

    new_password_hash = hash_password(new_password)

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        with connection:
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_password_hash, username),
            )

    return True, "Password reset successful."
