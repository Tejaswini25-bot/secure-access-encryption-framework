
import pyotp


def generate_mfa_secret():
    return pyotp.random_base32()


def get_totp_setup_uri(username, secret):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=username,
        issuer_name="Secure Access Framework",
    )


def verify_totp_code(secret, code):
    if not isinstance(secret, str) or not isinstance(code, str):
        return False

    if len(code) != 6 or not code.isdigit():
        return False

    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    except (ValueError, TypeError):
        return False
