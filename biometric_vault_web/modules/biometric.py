import hashlib
from pathlib import Path

from PIL import Image, ImageOps


def extract_features(path: str | Path) -> bytes:
    image = Image.open(path)
    grayscale = ImageOps.grayscale(image)
    normalized = ImageOps.autocontrast(grayscale)
    resized = normalized.resize((128, 128))
    return resized.tobytes()


def fingerprint_hash(path: str | Path) -> str:
    return hashlib.sha256(extract_features(path)).hexdigest()


def compare_fingerprint(stored_hash: str, uploaded_path: str | Path) -> tuple[bool, str]:
    candidate_hash = fingerprint_hash(uploaded_path)
    return stored_hash == candidate_hash, candidate_hash
