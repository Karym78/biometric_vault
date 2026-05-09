MAX_FAILED_ATTEMPTS = 3


def is_blocked(user: dict) -> bool:
    return bool(user.get("is_blocked"))


def should_block(failed_attempts: int) -> bool:
    return failed_attempts >= MAX_FAILED_ATTEMPTS
