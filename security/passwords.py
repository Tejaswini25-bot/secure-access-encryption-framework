from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError


password_hasher = PasswordHasher()


def hash_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    return password_hasher.hash(password)


def verify_password(password, stored_hash):
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False

    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, ValueError):
        return False
