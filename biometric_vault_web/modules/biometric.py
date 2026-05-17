import hashlib
from pathlib import Path

from PIL import Image, ImageOps


def fingerprint_hash(path: str | Path) -> str:
    image = Image.open(path)
    grayscale = ImageOps.grayscale(image)
    normalized = ImageOps.autocontrast(grayscale)
    image = normalized.resize((128, 128))
    return hashlib.sha256(image.tobytes()).hexdigest()
