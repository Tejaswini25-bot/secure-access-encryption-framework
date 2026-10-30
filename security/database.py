import sqlite3
from contextlib import closing
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent.parent / "users.db"


def create_database():
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    mfa_secret_encrypted TEXT,
                    mfa_enabled INTEGER NOT NULL DEFAULT 0
                        CHECK (mfa_enabled IN (0, 1))
                )
            """)

            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(users)"
                ).fetchall()
            }

            if "email" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN email TEXT"
                )

            if "mfa_secret_encrypted" not in columns:
                connection.execute(
                    "ALTER TABLE users "
                    "ADD COLUMN mfa_secret_encrypted TEXT"
                )

            if "mfa_enabled" not in columns:
                connection.execute("""
                    ALTER TABLE users
                    ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0
                        CHECK (mfa_enabled IN (0, 1))
                """)

            connection.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS
                idx_users_email_unique
                ON users(email)
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    username TEXT PRIMARY KEY,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                )
            """)

            # Store password-reset OTP hashes and expiry information.
            connection.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    username TEXT PRIMARY KEY,
                    otp_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                )
            """)


def add_user(username, password_hash, email=None):
    create_database()

    try:
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO users "
                    "(username, password_hash, email) "
                    "VALUES (?, ?, ?)",
                    (username, password_hash, email),
                )
        return True
    except sqlite3.IntegrityError:
        return False
