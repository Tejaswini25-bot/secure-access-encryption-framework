import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv


CREDENTIALS_FILE = (
    Path.home() / ".config/secure-access/email.env"
)


def send_password_reset_email(recipient, otp):
    """Send a password-reset OTP using Gmail SMTP."""

    load_dotenv(CREDENTIALS_FILE)

    sender = os.getenv("EMAIL_ADDRESS")
    app_password = os.getenv("EMAIL_APP_PASSWORD")

    if not sender or not app_password:
        raise RuntimeError("Email credentials are not configured.")

    if not isinstance(recipient, str) or "@" not in recipient:
        raise ValueError("Invalid recipient email address.")

    message = EmailMessage()
    message["Subject"] = "Password Reset Verification Code"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(f"""
Hello,

We received a request to reset your password.

Your verification code is:

{otp}

This code expires in 5 minutes.

If you did not request this password reset, please ignore this email.

Regards,
Secure Access Encryption Framework
""")

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        timeout=15,
    ) as server:
        server.login(sender, app_password)
        server.send_message(message)

    return True
