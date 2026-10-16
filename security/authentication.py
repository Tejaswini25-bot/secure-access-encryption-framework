
import sqlite3

from security.database import DATABASE_PATH, create_database
from security.passwords import verify_password
from security.secret_storage import decrypt_secret
from security.mfa import verify_totp_code


def login_user(username, password, mfa_code=None):
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Invalid username or password."

    create_database()

    try:
        with sqlite3.connect(DATABASE_PATH) as connection:
            row = connection.execute(
                "SELECT password_hash, mfa_secret_encrypted, mfa_enabled "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error:
        return False, "Login could not be completed."

    if row is None:
        return False, "Invalid username or password."

    password_hash, encrypted_secret, mfa_enabled = row

    if not verify_password(password, password_hash):
        return False, "Invalid username or password."

    if mfa_enabled == 1:
        if not isinstance(mfa_code, str):
            return False, "A valid MFA code is required."

        if not encrypted_secret:
            return False, "MFA verification could not be completed."

        try:
            secret = decrypt_secret(encrypted_secret)
        except (RuntimeError, ValueError):
            return False, "MFA verification could not be completed."

        if not verify_totp_code(secret, mfa_code):
            return False, "Invalid username or password."

    return True, "Login successful."
