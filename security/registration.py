
from app import is_valid_username
from security.database import add_user
from security.passwords import hash_password


def register_user(username, password):
    if not is_valid_username(username):
        return False, "Invalid username."

    if not isinstance(password, str) or len(password) < 12:
        return False, "Password must contain at least 12 characters."

    password_hash = hash_password(password)

    if not add_user(username, password_hash):
        return False, "Username already exists."

    return True, "Registration successful."
