import hashlib

from modules.database import create_log


def log_event(username: str | None, operation: str, status: str, message: str) -> None:
    digest = hashlib.sha256(f"{username}|{operation}|{status}|{message}".encode("utf-8")).hexdigest()
    create_log(username, operation, status, message, digest)
