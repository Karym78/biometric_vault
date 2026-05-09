from pathlib import Path
from uuid import uuid4

from PIL import Image

from modules.paths import WATERMARKED_DIR


def _message_to_bits(message: str) -> list[int]:
    payload = message.encode("utf-8")
    data = len(payload).to_bytes(4, "big") + payload
    return [(byte >> bit) & 1 for byte in data for bit in range(7, -1, -1)]


def embed_watermark(image_path: str | Path, message: str) -> Path:
    source = Path(image_path)
    image = Image.open(source).convert("RGB")
    pixels = list(image.get_flattened_data() if hasattr(image, "get_flattened_data") else image.getdata())
    bits = _message_to_bits(message)
    if len(bits) > len(pixels) * 3:
        raise ValueError("Fingerprint image is too small for this watermark.")

    output = []
    index = 0
    for pixel in pixels:
        channels = []
        for value in pixel:
            if index < len(bits):
                channels.append((value & 0xFE) | bits[index])
                index += 1
            else:
                channels.append(value)
        output.append(tuple(channels))

    image.putdata(output)
    destination = WATERMARKED_DIR / f"{source.stem}_{uuid4().hex[:10]}.png"
    image.save(destination)
    return destination
