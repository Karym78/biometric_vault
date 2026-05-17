from modules.matching_score import SECURITY_LEVELS


def security_level_rows() -> list[dict]:
    return [
        {
            "level": "low",
            "threshold": SECURITY_LEVELS["low"],
            "far": "Higher",
            "frr": "Lower",
            "use_case": "Easy demo access, less strict verification.",
        },
        {
            "level": "medium",
            "threshold": SECURITY_LEVELS["medium"],
            "far": "Balanced",
            "frr": "Balanced",
            "use_case": "Default university demo setting.",
        },
        {
            "level": "high",
            "threshold": SECURITY_LEVELS["high"],
            "far": "Lower",
            "frr": "Higher",
            "use_case": "Stricter protection, more rejected attempts.",
        },
    ]
