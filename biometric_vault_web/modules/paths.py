from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
FINGERPRINT_DIR = DATA_DIR / "fingerprints"
WATERMARKED_DIR = DATA_DIR / "watermarked"
ENCRYPTED_DIR = DATA_DIR / "encrypted_files"
DECRYPTED_DIR = DATA_DIR / "decrypted_files"
DATABASE_DIR = DATA_DIR / "database"
DATABASE_PATH = DATABASE_DIR / "biometric_vault.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"


def ensure_directories() -> None:
    for path in (
        FINGERPRINT_DIR,
        WATERMARKED_DIR,
        ENCRYPTED_DIR,
        DECRYPTED_DIR,
        DATABASE_DIR,
        UPLOAD_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
