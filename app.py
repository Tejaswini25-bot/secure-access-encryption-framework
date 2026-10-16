def show_mfa_status(enabled):
    if enabled:
        print("MFA status: enabled")
    else:
        print("MFA status: not enabled yet")


def has_reached_demo_threshold(attempts, threshold=5):
    return attempts >= threshold


def is_valid_username(username):
    if not isinstance(username, str):
        return False

    if not 3 <= len(username) <= 32:
        return False

    letters_and_digits = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
    )
    allowed_characters = letters_and_digits + "_.-"

    if username[0] not in letters_and_digits:
        return False

    return all(
        character in allowed_characters
        for character in username
    )


def main():
    project_name = "Secure Access & Data Encryption Framework"
    project_status = "Foundation setup"

    failed_login_attempts = 3
    mfa_enabled = False

    planned_features = [
        "Secure login and password hashing",
        "Multi-factor authentication",
        "File encryption",
        "Vulnerability assessment",
    ]

    print("Project:", project_name)
    print("Status:", project_status)
    print("Example failed login attempts:", failed_login_attempts)
    print("MFA enabled:", mfa_enabled)

    show_mfa_status(mfa_enabled)

    if has_reached_demo_threshold(failed_login_attempts):
        print("Example status: threshold reached")
    else:
        print("Example status: below the example threshold")

    username = input("Enter a demo username: ")

    if is_valid_username(username):
        print("Username input accepted.")
    else:
        print("Invalid username. Follow the username rules.")

    print("Planned features:", planned_features)


if __name__ == "__main__":
    main()
