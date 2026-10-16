
import sqlite3

from security.database import DATABASE_PATH
from security.passwords import verify_password


def login_user(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return False, "Invalid username or password."

    try:
        with sqlite3.connect(DATABASE_PATH) as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error:
        return False, "Login could not be completed."

    if row is None:
        return False, "Invalid username or password."

    if not verify_password(password, row[0]):
        return False, "Invalid username or password."

    return True, "Login successful."
