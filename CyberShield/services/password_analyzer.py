"""Password strength analysis module."""

import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "login", "abc123",
    "password123", "admin123", "cyber123", "internship",
}


def analyze_password(password: str) -> dict:
    checks = []
    score = 0

    length = len(password)
    if length >= 12:
        score += 25
        checks.append({"name": "Length", "passed": True, "detail": f"{length} characters (good)"})
    elif length >= 8:
        score += 15
        checks.append({"name": "Length", "passed": True, "detail": f"{length} characters (acceptable)"})
    else:
        checks.append({"name": "Length", "passed": False, "detail": f"{length} characters (too short)"})

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    for name, passed, pts in [
        ("Lowercase letters", has_lower, 10),
        ("Uppercase letters", has_upper, 10),
        ("Numbers", has_digit, 10),
        ("Special characters", has_special, 15),
    ]:
        if passed:
            score += pts
        checks.append({"name": name, "passed": passed, "detail": "Present" if passed else "Missing"})

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 20)
        checks.append({"name": "Common password", "passed": False, "detail": "Found in common password list"})

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        checks.append({"name": "Repeated characters", "passed": False, "detail": "Avoid repeating patterns"})

    entropy = _estimate_entropy(password)
    score = max(0, min(100, score + min(20, int(entropy / 2))))

    if score >= 80:
        strength, risk = "Strong", "low"
    elif score >= 60:
        strength, risk = "Good", "low"
    elif score >= 40:
        strength, risk = "Fair", "medium"
    elif score >= 20:
        strength, risk = "Weak", "high"
    else:
        strength, risk = "Very Weak", "critical"

    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters")
    if not has_upper:
        suggestions.append("Add uppercase letters")
    if not has_digit:
        suggestions.append("Add numbers")
    if not has_special:
        suggestions.append("Add special characters (!@#$%)")
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append("Avoid common passwords")

    return {
        "score": score,
        "strength": strength,
        "risk_level": risk,
        "entropy_bits": round(entropy, 1),
        "checks": checks,
        "suggestions": suggestions,
        "summary": f"Password strength: {strength} ({score}/100)",
    }


def _estimate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)
