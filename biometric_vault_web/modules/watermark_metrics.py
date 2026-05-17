import math
from pathlib import Path

from PIL import Image


def message_bits(message: str) -> list[int]:
    return [(byte >> bit) & 1 for byte in message.encode("utf-8") for bit in range(7, -1, -1)]


def calculate_psnr(original_path: str | Path, watermarked_path: str | Path) -> float:
    original = Image.open(original_path).convert("RGB")
    watermarked = Image.open(watermarked_path).convert("RGB").resize(original.size)
    original_pixels = list(original.getdata())
    watermarked_pixels = list(watermarked.getdata())
    squared_error = 0
    count = 0
    for original_pixel, watermarked_pixel in zip(original_pixels, watermarked_pixels):
        for original_value, watermarked_value in zip(original_pixel, watermarked_pixel):
            squared_error += (original_value - watermarked_value) ** 2
            count += 1
    mse = squared_error / count if count else 0
    if mse == 0:
        return 99.0
    return round(10 * math.log10((255 * 255) / mse), 2)


def bit_error_rate(expected: str, extracted: str) -> float:
    expected_bits = message_bits(expected)
    extracted_bits = message_bits(extracted)
    size = max(len(expected_bits), len(extracted_bits), 1)
    errors = 0
    for index in range(size):
        left = expected_bits[index] if index < len(expected_bits) else 0
        right = extracted_bits[index] if index < len(extracted_bits) else 0
        if left != right:
            errors += 1
    return round(errors / size, 4)


def normalized_correlation(expected: str, extracted: str) -> float:
    expected_bits = message_bits(expected)
    extracted_bits = message_bits(extracted)
    size = max(len(expected_bits), len(extracted_bits), 1)
    numerator = 0
    expected_energy = 0
    extracted_energy = 0
    for index in range(size):
        left = expected_bits[index] if index < len(expected_bits) else 0
        right = extracted_bits[index] if index < len(extracted_bits) else 0
        numerator += left * right
        expected_energy += left * left
        extracted_energy += right * right
    denominator = math.sqrt(expected_energy * extracted_energy)
    return round(numerator / denominator, 4) if denominator else 0.0
