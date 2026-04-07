"""
dictionary_checker.py — Dictionary / Common Password Checker Module

Loads a list of common passwords and a general dictionary wordlist, then
provides two lookup functions used by the analyzer.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve paths relative to this file so the package works from any CWD
# ---------------------------------------------------------------------------
_BASE_DIR    = Path(__file__).resolve().parent.parent
_COMMON_FILE = _BASE_DIR / "data" / "common_passwords.txt"
_WORDS_FILE  = _BASE_DIR / "data" / "wordlist.txt"


def _load_set(filepath: Path) -> set[str]:
    """Load a text file (one entry per line) into a lowercase set."""
    entries = set()
    try:
        with filepath.open("r", encoding="utf-8") as fh:
            for line in fh:
                word = line.strip().lower()
                if word:
                    entries.add(word)
    except OSError:
        pass   # Gracefully degrade if file is missing
    return entries


# Load once at import time for efficiency
_COMMON_PASSWORDS: set = _load_set(_COMMON_FILE)
_DICTIONARY_WORDS: set = _load_set(_WORDS_FILE)


def is_common_password(password: str) -> bool:
    """Return True if the password (lowercase) is in the common-password list."""
    return password.lower() in _COMMON_PASSWORDS


def contains_dictionary_word(password: str, min_word_length: int = 4) -> bool:
    """
    Return True if the password contains any dictionary word of at least
    `min_word_length` characters.  Checks only words long enough to be
    meaningful so we don't flag every password containing 'the'.
    """
    lower = password.lower()
    for word in _DICTIONARY_WORDS:
        if len(word) >= min_word_length and word in lower:
            return True
    return False


def get_common_passwords() -> set:
    """Return the full set of common passwords (read-only copy)."""
    return frozenset(_COMMON_PASSWORDS)


def get_dictionary_words() -> set:
    """Return the full set of dictionary words (read-only copy)."""
    return frozenset(_DICTIONARY_WORDS)
