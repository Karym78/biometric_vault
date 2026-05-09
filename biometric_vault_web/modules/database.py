import sqlite3
from datetime import datetime, timezone

from modules.paths import DATABASE_PATH, ensure_directories


def get_connection() -> sqlite3.Connection:
    ensure_directories()
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                fingerprint_hash TEXT NOT NULL,
                watermarked_image_path TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                watermarked_image_path TEXT NOT NULL,
                label TEXT,
                is_primary INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                original_filename TEXT NOT NULL,
                encrypted_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                operation TEXT,
                status TEXT,
                message TEXT,
                log_hash TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        _migrate_existing_user_fingerprints(connection)


def _migrate_existing_user_fingerprints(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT id, fingerprint_hash, watermarked_image_path
        FROM users
        WHERE id NOT IN (SELECT user_id FROM user_fingerprints)
        """
    ).fetchall()
    for row in rows:
        connection.execute(
            """
            INSERT INTO user_fingerprints
                (user_id, fingerprint_hash, watermarked_image_path, label, is_primary, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"],
                row["fingerprint_hash"],
                row["watermarked_image_path"],
                "Primary fingerprint",
                1,
                now_iso(),
            ),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


def create_user(username: str, fingerprint_hash: str, watermarked_path: str) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (username, fingerprint_hash, watermarked_image_path, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, fingerprint_hash, watermarked_path, now_iso()),
        )
        user_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO user_fingerprints
                (user_id, fingerprint_hash, watermarked_image_path, label, is_primary, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, fingerprint_hash, watermarked_path, "Primary fingerprint", 1, now_iso()),
        )
        return user_id


def add_user_fingerprint(user_id: int, fingerprint_hash: str, watermarked_path: str, label: str) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO user_fingerprints
                (user_id, fingerprint_hash, watermarked_image_path, label, is_primary, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, fingerprint_hash, watermarked_path, label, 0, now_iso()),
        )
        return int(cursor.lastrowid)


def list_user_fingerprints(user_id: int) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM user_fingerprints
            WHERE user_id = ?
            ORDER BY is_primary DESC, created_at ASC
            """,
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def find_fingerprint_owner(fingerprint_hash: str) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                user_fingerprints.id AS fingerprint_id,
                user_fingerprints.user_id,
                user_fingerprints.label,
                users.username
            FROM user_fingerprints
            JOIN users ON users.id = user_fingerprints.user_id
            WHERE user_fingerprints.fingerprint_hash = ?
            LIMIT 1
            """,
            (fingerprint_hash,),
        ).fetchone()
        return row_to_dict(row)


def get_user(username: str) -> dict | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return row_to_dict(row)


def get_user_by_id(user_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return row_to_dict(row)


def increment_failed_attempts(username: str) -> int:
    with get_connection() as connection:
        connection.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
            (username,),
        )
        row = connection.execute(
            "SELECT failed_attempts FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return int(row["failed_attempts"])


def reset_failed_attempts(username: str) -> None:
    with get_connection() as connection:
        connection.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))


def block_user(username: str) -> None:
    with get_connection() as connection:
        connection.execute("UPDATE users SET is_blocked = 1 WHERE username = ?", (username,))


def create_file_record(user_id: int, original_filename: str, encrypted_path: str) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO encrypted_files (user_id, original_filename, encrypted_path, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, original_filename, encrypted_path, now_iso()),
        )
        return int(cursor.lastrowid)


def list_files(user_id: int) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM encrypted_files WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_file_for_user(file_id: int, user_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM encrypted_files WHERE id = ? AND user_id = ?",
            (file_id, user_id),
        ).fetchone()
        return row_to_dict(row)


def create_log(username: str | None, operation: str, status: str, message: str, log_hash: str) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_logs (username, operation, status, message, log_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, operation, status, message, log_hash, now_iso()),
        )
        return int(cursor.lastrowid)


def list_logs(limit: int = 200) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM security_logs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
