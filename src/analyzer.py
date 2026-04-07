"""
analyzer.py — Password Strength Analyzer Module

Evaluates a password and returns:
  - a numeric score (0–100)
  - a strength label (Very Weak / Weak / Medium / Strong / Very Strong)
  - reasons explaining the score
  - suggestions for improvement
"""

import re
import math
from src.dictionary_checker import is_common_password, contains_dictionary_word


# ---------------------------------------------------------------------------
# Scoring weights (must sum to 100)
# ---------------------------------------------------------------------------
WEIGHT_LENGTH     = 30   # Length is the single most important factor
WEIGHT_DIVERSITY  = 25   # Character-class diversity (lower/upper/digit/symbol)
WEIGHT_ENTROPY    = 20   # Shannon-like entropy estimate
WEIGHT_PATTERNS   = 15   # Penalty for repeated/sequential patterns
WEIGHT_DICTIONARY = 10   # Penalty for common / dictionary words


def analyze(password: str) -> dict:
    """
    Analyze a password and return a detailed result dictionary.

    Returns:
        {
            "score": int (0–100),
            "label": str,
            "reasons": list[str],
            "suggestions": list[str],
            "details": dict   # raw sub-scores for transparency
        }
    """
    reasons     = []
    suggestions = []
    details     = {}

    # --- 1. Length sub-score ---
    length     = len(password)
    len_score  = _score_length(length)
    details["length_score"] = len_score
    if length < 8:
        reasons.append(f"Password is too short ({length} characters).")
        suggestions.append("Use at least 8 characters; 12+ is recommended.")
    elif length < 12:
        reasons.append(f"Password length is acceptable ({length} characters).")
        suggestions.append("Consider extending to 12+ characters for extra security.")
    else:
        reasons.append(f"Good password length ({length} characters).")

    # --- 2. Character-class diversity sub-score ---
    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'\d',   password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    num_classes   = sum([has_lower, has_upper, has_digit, has_symbol])
    div_score     = _score_diversity(num_classes)
    details["diversity_score"] = div_score

    missing_classes = []
    if not has_lower:
        missing_classes.append("lowercase letters")
    if not has_upper:
        missing_classes.append("uppercase letters")
    if not has_digit:
        missing_classes.append("digits")
    if not has_symbol:
        missing_classes.append("special characters (e.g. !@#$)")

    if missing_classes:
        reasons.append(
            f"Missing character types: {', '.join(missing_classes)}."
        )
        suggestions.append(
            f"Add {', '.join(missing_classes)} to increase complexity."
        )
    else:
        reasons.append("Uses all four character classes (lower, upper, digit, symbol).")

    # --- 3. Entropy sub-score ---
    charset_size  = _effective_charset(has_lower, has_upper, has_digit, has_symbol)
    entropy_bits  = length * math.log2(charset_size) if length > 0 else 0
    ent_score     = _score_entropy(entropy_bits)
    details["entropy_score"] = ent_score
    details["entropy_bits"]  = round(entropy_bits, 2)
    reasons.append(
        f"Estimated entropy: {entropy_bits:.1f} bits "
        f"(charset size ≈ {charset_size})."
    )

    # --- 4. Pattern penalty ---
    pattern_penalty, pattern_reasons = _check_patterns(password)
    pat_score             = max(0, WEIGHT_PATTERNS - pattern_penalty)
    details["pattern_score"] = pat_score
    reasons.extend(pattern_reasons)
    if pattern_penalty > 0:
        suggestions.append(
            "Avoid repeated characters, sequential runs, and keyboard walks."
        )

    # --- 5. Dictionary / common-password penalty ---
    dict_penalty, dict_reasons = _check_dictionary(password)
    dict_score             = max(0, WEIGHT_DICTIONARY - dict_penalty)
    details["dictionary_score"] = dict_score
    reasons.extend(dict_reasons)
    if dict_penalty > 0:
        suggestions.append(
            "Avoid dictionary words, common passwords, and simple substitutions."
        )

    # --- Final score ---
    raw_score = (
        len_score
        + div_score
        + ent_score
        + pat_score
        + dict_score
    )

    # Cap scores for passwords that are known-common or heavily penalized
    if is_common_password(password.lower()):
        # A common password is never better than Weak regardless of other factors
        raw_score = min(raw_score, 25)

    score = min(100, max(0, round(raw_score)))
    label = _score_to_label(score)

    # Generic suggestion if still weak
    if score < 40 and not suggestions:
        suggestions.append(
            "Try a passphrase: combine several random words with numbers and symbols."
        )
    suggestions = list(dict.fromkeys(suggestions))

    return {
        "score":       score,
        "label":       label,
        "reasons":     reasons,
        "suggestions": suggestions,
        "details":     details,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _score_length(length: int) -> float:
    """Map password length to a score out of WEIGHT_LENGTH (30)."""
    if length == 0:
        return 0
    if length < 6:
        return WEIGHT_LENGTH * 0.10
    if length < 8:
        return WEIGHT_LENGTH * 0.30
    if length < 10:
        return WEIGHT_LENGTH * 0.55
    if length < 12:
        return WEIGHT_LENGTH * 0.75
    if length < 16:
        return WEIGHT_LENGTH * 0.90
    return WEIGHT_LENGTH * 1.00


def _score_diversity(num_classes: int) -> float:
    """Map number of character classes (0–4) to a score out of WEIGHT_DIVERSITY (25)."""
    ratios = {0: 0.0, 1: 0.20, 2: 0.50, 3: 0.80, 4: 1.00}
    return WEIGHT_DIVERSITY * ratios.get(num_classes, 0)


def _effective_charset(lower, upper, digit, symbol) -> int:
    """Estimate the effective charset size for entropy calculation."""
    size = 0
    if lower:  size += 26
    if upper:  size += 26
    if digit:  size += 10
    if symbol: size += 32
    return max(size, 1)


def _score_entropy(bits: float) -> float:
    """Map entropy bits to a score out of WEIGHT_ENTROPY (20)."""
    if bits < 20:
        return WEIGHT_ENTROPY * 0.05
    if bits < 30:
        return WEIGHT_ENTROPY * 0.20
    if bits < 40:
        return WEIGHT_ENTROPY * 0.45
    if bits < 50:
        return WEIGHT_ENTROPY * 0.65
    if bits < 60:
        return WEIGHT_ENTROPY * 0.85
    return WEIGHT_ENTROPY * 1.00


def _check_patterns(password: str) -> tuple[float, list]:
    """
    Detect bad patterns and return (penalty, reasons).
    Maximum penalty is WEIGHT_PATTERNS (15).
    """
    penalty = 0
    reasons = []
    lower   = password.lower()

    # Repeated characters: e.g. "aaaa", "1111"
    if re.search(r'(.)\1{2,}', password):
        penalty += 5
        reasons.append("Contains repeated characters (e.g. 'aaa' or '111').")

    # Sequential letters: abc, xyz
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|'
                 r'opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower):
        penalty += 5
        reasons.append("Contains sequential alphabetic run (e.g. 'abc').")

    # Sequential digits: 123, 234, …, 890
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        penalty += 5
        reasons.append("Contains sequential digit run (e.g. '123').")

    # Keyboard walks: qwerty, asdf, zxcv
    keyboard_walks = ['qwerty', 'qwert', 'asdfgh', 'asdf', 'zxcvbn', 'zxcv',
                      'yuiop', 'hjkl']
    for walk in keyboard_walks:
        if walk in lower:
            penalty += 5
            reasons.append(f"Contains keyboard walk ('{walk}').")
            break

    return min(penalty, WEIGHT_PATTERNS), reasons


def _check_dictionary(password: str) -> tuple[float, list]:
    """
    Check against common passwords and dictionary words.
    Returns (penalty, reasons).  Maximum penalty is WEIGHT_DICTIONARY (10).
    """
    penalty = 0
    reasons = []
    lower   = password.lower()

    if is_common_password(lower):
        penalty += 10
        reasons.append("This is a well-known common password — very easy to guess.")
    elif contains_dictionary_word(lower):
        penalty += 5
        reasons.append("Password contains a common dictionary word.")

    return min(penalty, WEIGHT_DICTIONARY), reasons


def _score_to_label(score: int) -> str:
    """Convert numeric score to a human-readable strength label."""
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Medium"
    if score < 80:
        return "Strong"
    return "Very Strong"
