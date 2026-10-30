
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"SAEFENC1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit key


def derive_key(password, salt):
    """Derive a secure 256-bit key from a password using Scrypt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )

    return kdf.derive(password.encode("utf-8"))


def write_output(output_path, data):
    """Create a new output file without overwriting existing files."""
    output_path = Path(output_path)

    file_descriptor = os.open(
        output_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(file_descriptor, "wb") as output_file:
            output_file.write(data)
    except Exception:
        output_path.unlink(missing_ok=True)
        raise


def encrypt_file(input_path, output_path, password):
    """Encrypt a file using AES-256-GCM."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("Input file does not exist.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files must be different.")

    plaintext = input_path.read_bytes()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, plaintext, MAGIC)

    encrypted_data = MAGIC + salt + nonce + ciphertext

    write_output(output_path, encrypted_data)

    return True


def decrypt_file(input_path, output_path, password):
    """Decrypt a file and verify its authenticity."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("Encrypted file does not exist.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files must be different.")

    encrypted_data = input_path.read_bytes()

    minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

    if len(encrypted_data) < minimum_size:
        raise ValueError("Invalid or corrupted encrypted file.")

    if not encrypted_data.startswith(MAGIC):
        raise ValueError("Unsupported or invalid encrypted file format.")

    offset = len(MAGIC)

    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = encrypted_data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = encrypted_data[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: incorrect password or corrupted file."
        ) from None

    write_output(output_path, plaintext)

    return True

