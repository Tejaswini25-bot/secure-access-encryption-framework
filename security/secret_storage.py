
import os

from cryptography.fernet import Fernet, InvalidToken


def _get_fernet():
    key = os.environ.get("MFA_ENCRYPTION_KEY")

    if not key:
        raise RuntimeError(
            "MFA_ENCRYPTION_KEY environment variable is not set."
        )

    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(
            "MFA_ENCRYPTION_KEY is invalid."
        ) from exc


def encrypt_secret(secret):
    if not isinstance(secret, str) or not secret:
        raise ValueError("Secret must be a non-empty string.")

    return _get_fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted_secret):
    if not isinstance(encrypted_secret, str) or not encrypted_secret:
        raise ValueError("Encrypted secret must be a non-empty string.")

    try:
        return _get_fernet().decrypt(
            encrypted_secret.encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Unable to decrypt the secret.") from exc
