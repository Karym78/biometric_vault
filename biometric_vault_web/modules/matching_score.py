from pathlib import Path

from modules.biometric_preprocessing import extract_minutiae, foreground_bits


SECURITY_LEVELS = {
    "low": 0.60,
    "medium": 0.75,
    "high": 0.85,
}

SPATIAL_TOLERANCE = 5


def threshold_for_level(level: str | None) -> float:
    return SECURITY_LEVELS.get(level or "medium", SECURITY_LEVELS["medium"])


def _texture_fallback_score(reference_path: str | Path, test_path: str | Path) -> dict:
    reference_bits = foreground_bits(reference_path)
    test_bits = foreground_bits(test_path)
    nref = sum(reference_bits)
    ntest = sum(test_bits)
    nmatch = sum(1 for ref, test in zip(reference_bits, test_bits) if ref and test)
    return _score_from_counts(nref, ntest, nmatch) | {"method": "Texture fallback"}


def _score_from_counts(nref: int, ntest: int, nmatch: int) -> dict:
    score_min = nmatch / min(nref, ntest) if min(nref, ntest) else 0.0
    score_dice = (2 * nmatch) / (nref + ntest) if (nref + ntest) else 0.0
    score_geo = nmatch / ((nref * ntest) ** 0.5) if (nref and ntest) else 0.0
    return {
        "nref": nref,
        "ntest": ntest,
        "nmatch": nmatch,
        "score_min": round(score_min, 4),
        "score_dice": round(score_dice, 4),
        "score_geo": round(score_geo, 4),
        "score": round(score_dice, 4),
    }


def _distance_squared(left: dict, right: dict) -> int:
    return (left["x"] - right["x"]) ** 2 + (left["y"] - right["y"]) ** 2


def _matching_minutiae(reference: list[dict], test: list[dict]) -> int:
    used_test_indexes = set()
    matches = 0
    tolerance_squared = SPATIAL_TOLERANCE * SPATIAL_TOLERANCE
    for ref_point in reference:
        best_index = None
        best_distance = tolerance_squared + 1
        for index, test_point in enumerate(test):
            if index in used_test_indexes or ref_point["type"] != test_point["type"]:
                continue
            distance = _distance_squared(ref_point, test_point)
            if distance <= tolerance_squared and distance < best_distance:
                best_index = index
                best_distance = distance
        if best_index is not None:
            used_test_indexes.add(best_index)
            matches += 1
    return matches


def compare_fingerprint_images(
    reference_path: str | Path,
    test_path: str | Path,
    threshold: float,
) -> dict:
    reference_minutiae = extract_minutiae(reference_path)
    test_minutiae = extract_minutiae(test_path)
    nref = len(reference_minutiae)
    ntest = len(test_minutiae)
    if nref < 5 or ntest < 5:
        result = _texture_fallback_score(reference_path, test_path)
    else:
        nmatch = _matching_minutiae(reference_minutiae, test_minutiae)
        result = _score_from_counts(nref, ntest, nmatch) | {"method": "Minutiae Crossing Number"}
    result["reference_endings"] = sum(1 for point in reference_minutiae if point["type"] == "ending")
    result["reference_bifurcations"] = sum(1 for point in reference_minutiae if point["type"] == "bifurcation")
    result["test_endings"] = sum(1 for point in test_minutiae if point["type"] == "ending")
    result["test_bifurcations"] = sum(1 for point in test_minutiae if point["type"] == "bifurcation")
    result["threshold"] = threshold
    result["decision"] = result["score"] >= threshold
    result["spatial_tolerance"] = SPATIAL_TOLERANCE
    return {
        **result,
    }
