from pathlib import Path
from uuid import uuid4

from PIL import Image, ImageFilter, ImageOps

from modules.paths import UPLOAD_DIR


PREPROCESS_SIZE = (128, 128)
MINUTIA_DISTANCE = 5


def preprocess_image(image_path: str | Path) -> Image.Image:
    image = Image.open(image_path).convert("L")
    image = ImageOps.autocontrast(image)
    image = image.filter(ImageFilter.MedianFilter(size=3))
    image = image.resize(PREPROCESS_SIZE)
    return image.point(lambda value: 0 if value < 128 else 255, mode="1")


def foreground_bits(image_path: str | Path) -> list[int]:
    image = preprocess_image(image_path).convert("L")
    return [1 if value == 0 else 0 for value in image.getdata()]


def binary_matrix(image_path: str | Path) -> list[list[int]]:
    image = preprocess_image(image_path).convert("L")
    pixels = list(image.getdata())
    width, height = image.size
    return [
        [1 if pixels[y * width + x] == 0 else 0 for x in range(width)]
        for y in range(height)
    ]


def _neighbors(matrix: list[list[int]], x: int, y: int) -> list[int]:
    return [
        matrix[y - 1][x],
        matrix[y - 1][x + 1],
        matrix[y][x + 1],
        matrix[y + 1][x + 1],
        matrix[y + 1][x],
        matrix[y + 1][x - 1],
        matrix[y][x - 1],
        matrix[y - 1][x - 1],
    ]


def skeletonize(matrix: list[list[int]]) -> list[list[int]]:
    skeleton = [row[:] for row in matrix]
    height = len(skeleton)
    width = len(skeleton[0]) if height else 0
    changed = True
    while changed:
        changed = False
        for step in (0, 1):
            to_remove = []
            for y in range(1, height - 1):
                for x in range(1, width - 1):
                    if skeleton[y][x] == 0:
                        continue
                    p = _neighbors(skeleton, x, y)
                    transitions = sum(1 for index in range(8) if p[index] == 0 and p[(index + 1) % 8] == 1)
                    neighbor_count = sum(p)
                    if not (2 <= neighbor_count <= 6 and transitions == 1):
                        continue
                    if step == 0:
                        keep = p[0] * p[2] * p[4] == 0 and p[2] * p[4] * p[6] == 0
                    else:
                        keep = p[0] * p[2] * p[6] == 0 and p[0] * p[4] * p[6] == 0
                    if keep:
                        to_remove.append((x, y))
            if to_remove:
                changed = True
                for x, y in to_remove:
                    skeleton[y][x] = 0
    return skeleton


def _far_from_existing(points: list[dict], x: int, y: int, kind: str) -> bool:
    for point in points:
        if point["type"] != kind:
            continue
        if abs(point["x"] - x) <= MINUTIA_DISTANCE and abs(point["y"] - y) <= MINUTIA_DISTANCE:
            return False
    return True


def extract_minutiae(image_path: str | Path) -> list[dict]:
    skeleton = skeletonize(binary_matrix(image_path))
    height = len(skeleton)
    width = len(skeleton[0]) if height else 0
    minutiae = []
    for y in range(2, height - 2):
        for x in range(2, width - 2):
            if skeleton[y][x] == 0:
                continue
            p = _neighbors(skeleton, x, y)
            crossing_number = sum(abs(p[index] - p[(index + 1) % 8]) for index in range(8)) // 2
            kind = None
            if crossing_number == 1:
                kind = "ending"
            elif crossing_number == 3:
                kind = "bifurcation"
            if kind and _far_from_existing(minutiae, x, y, kind):
                minutiae.append({"x": x, "y": y, "type": kind})
    return minutiae


def save_preprocessed_preview(image_path: str | Path) -> Path:
    image = preprocess_image(image_path).convert("L")
    source = Path(image_path)
    destination = UPLOAD_DIR / f"preprocessed_{source.stem}_{uuid4().hex[:8]}.png"
    image.save(destination)
    return destination
