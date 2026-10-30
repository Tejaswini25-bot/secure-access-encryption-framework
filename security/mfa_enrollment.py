
import sqlite3
from contextlib import closing

from security.database import DATABASE_PATH, create_database
from security.mfa import (
    generate_mfa_secret,
    get_totp_setup_uri,
    verify_totp_code,
)
from security.secret_storage import encrypt_secret, decrypt_secret


def begin_mfa_enrollment(username):
    if not isinstance(username, str) or not username:
        return False, "Invalid username.", None

    create_database()

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                row = connection.execute(
                    "SELECT mfa_enabled, mfa_secret_encrypted "
                    "FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
    except sqlite3.Error:
        return False, "MFA enrollment could not be started.", None

    if row is None:
        return False, "User not found.", None

    if row[0] == 1:
        return False, "MFA is already enabled.", None

    if row[1] is not None:
        return False, (
            "An MFA enrollment is already pending. "
            "Complete or reset it before starting another."
        ), None

    secret = generate_mfa_secret()

    try:
        encrypted_secret = encrypt_secret(secret)
    except (RuntimeError, ValueError):
        return False, "MFA secret encryption is unavailable.", None

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute(
                    "UPDATE users SET mfa_secret_encrypted = ? "
                    "WHERE username = ? AND mfa_enabled = 0 "
                    "AND mfa_secret_encrypted IS NULL",
                    (encrypted_secret, username),
                )

                if connection.execute(
                    "SELECT changes()"
                ).fetchone()[0] != 1:
                    return (
                        False,
                        "MFA enrollment could not be started.",
                        None,
                    )
    except sqlite3.Error:
        return False, "MFA enrollment could not be saved.", None

    setup_uri = get_totp_setup_uri(username, secret)
    return True, "MFA enrollment started.", setup_uri


def confirm_mfa_enrollment(username, code):
    if not isinstance(username, str) or not username:
        return False, "Invalid username."

    create_database()

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                row = connection.execute(
                    "SELECT mfa_secret_encrypted, mfa_enabled "
                    "FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
    except sqlite3.Error:
        return False, "MFA confirmation could not be completed."

    if row is None:
        return False, "MFA enrollment was not found."

    encrypted_secret, enabled = row

    if enabled == 1:
        return False, "MFA is already enabled."

    if not encrypted_secret:
        return False, "Start MFA enrollment first."

    try:
        secret = decrypt_secret(encrypted_secret)
    except (RuntimeError, ValueError):
        return False, "MFA secret could not be decrypted."

    if not verify_totp_code(secret, code):
        return False, "Invalid MFA code."

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute(
                    "UPDATE users SET mfa_enabled = 1 "
                    "WHERE username = ? AND mfa_enabled = 0 "
                    "AND mfa_secret_encrypted = ?",
                    (username, encrypted_secret),
                )

                if connection.execute(
                    "SELECT changes()"
                ).fetchone()[0] != 1:
                    return False, "MFA could not be enabled."
    except sqlite3.Error:
        return False, "MFA could not be enabled."

    return True, "MFA enabled successfully."

