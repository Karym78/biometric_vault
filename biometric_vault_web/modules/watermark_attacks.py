import random
from pathlib import Path
from uuid import uuid4

from PIL import Image

from modules.paths import UPLOAD_DIR


def _destination(source: Path, attack_name: str, suffix: str = ".png") -> Path:
    return UPLOAD_DIR / f"{source.stem}_{attack_name}_{uuid4().hex[:8]}{suffix}"


def jpeg_compression(image_path: str | Path) -> Path:
    source = Path(image_path)
    destination = _destination(source, "jpeg", ".jpg")
    Image.open(source).convert("RGB").save(destination, quality=40)
    return destination


def gaussian_noise(image_path: str | Path) -> Path:
    source = Path(image_path)
    image = Image.open(source).convert("RGB")
    output = []
    for red, green, blue in image.getdata():
        noise = int(random.gauss(0, 8))
        output.append(
            (
                max(0, min(255, red + noise)),
                max(0, min(255, green + noise)),
                max(0, min(255, blue + noise)),
            )
        )
    image.putdata(output)
    destination = _destination(source, "noise")
    image.save(destination)
    return destination


def resize_attack(image_path: str | Path) -> Path:
    source = Path(image_path)
    image = Image.open(source).convert("RGB")
    small = image.resize((max(1, image.width // 2), max(1, image.height // 2)))
    attacked = small.resize(image.size)
    destination = _destination(source, "resize")
    attacked.save(destination)
    return destination


def crop_attack(image_path: str | Path) -> Path:
    source = Path(image_path)
    image = Image.open(source).convert("RGB")
    left = image.width // 10
    top = image.height // 10
    cropped = image.crop((left, top, image.width - left, image.height - top)).resize(image.size)
    destination = _destination(source, "crop")
    cropped.save(destination)
    return destination


ATTACKS = {
    "jpeg": jpeg_compression,
    "noise": gaussian_noise,
    "resize": resize_attack,
    "crop": crop_attack,
}
