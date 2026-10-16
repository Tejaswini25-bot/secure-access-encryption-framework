def show_mfa_status(enabled):
    if enabled:
        print("MFA status: enabled")
    else:
        print("MFA status: not enabled yet")


def has_reached_demo_threshold(attempts, threshold=5):
    return attempts >= threshold


def is_nonempty_username(username):
    return bool(username.strip())


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

    threshold_reached = has_reached_demo_threshold(
        failed_login_attempts
    )

    if threshold_reached:
        print("Example status: threshold reached")
    else:
        print("Example status: below the example threshold")

    username = input("Enter a demo username: ")

    if is_nonempty_username(username):
        print("Username input accepted.")
    else:
        print("Username cannot be empty or whitespace.")

    print("Planned features:", planned_features)


if __name__ == "__main__":
    main()
