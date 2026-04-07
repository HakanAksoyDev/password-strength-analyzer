"""
dictionary_attack.py — Dictionary Attack Demonstration Module

⚠️  ETHICAL WARNING ⚠️
This module is provided SOLELY for educational purposes in a controlled,
local environment.  It demonstrates why passwords that match common words
are trivially cracked.  Do NOT use this code against real accounts, systems,
or hashes obtained without explicit written permission.

The attack works by hashing each word in a local wordlist and comparing it
to the target hash — a classic "offline dictionary attack."
"""

import time

from src.hasher import sha256_hash
from src.dictionary_checker import get_common_passwords, get_dictionary_words


def dictionary_attack(
    target_hash: str,
    extra_words: list[str] | None = None,
) -> dict:
    """
    Attempt to crack a SHA-256 hash using the bundled wordlists.

    Args:
        target_hash: Hex SHA-256 digest of the target password.
        extra_words: Optional additional candidate words.

    Returns:
        {
            "found":    bool,
            "password": str | None,
            "attempts": int,
            "time_sec": float,
        }
    """
    # Build combined candidate list: common passwords + dictionary + extras
    candidates = list(get_common_passwords()) + list(get_dictionary_words())
    if extra_words:
        candidates.extend(extra_words)

    # Also add simple leet-speak and capitalisation variants for each word
    augmented = []
    for word in candidates:
        augmented.append(word)
        augmented.append(word.capitalize())
        augmented.append(word + "1")
        augmented.append(word + "123")
        augmented.append(word + "!")
        # Simple leet substitutions
        augmented.append(
            word.replace("a", "@").replace("e", "3").replace("o", "0").replace("i", "1")
        )
    candidates = augmented

    start    = time.perf_counter()
    attempts = 0

    for candidate in candidates:
        attempts += 1
        if sha256_hash(candidate) == target_hash:
            elapsed = time.perf_counter() - start
            return {
                "found":    True,
                "password": candidate,
                "attempts": attempts,
                "time_sec": round(elapsed, 4),
            }

    elapsed = time.perf_counter() - start
    return {
        "found":    False,
        "password": None,
        "attempts": attempts,
        "time_sec": round(elapsed, 4),
    }


def demo_dictionary_attack(passwords: list[str]) -> list[dict]:
    """
    Run a dictionary-attack demo on a list of plaintext passwords.

    For each password:
      1. Hash it with SHA-256.
      2. Try to crack the hash via dictionary attack.
      3. Collect and return results.

    Args:
        passwords: List of plaintext passwords to demo.

    Returns:
        List of result dicts (one per password).
    """
    results = []
    for pwd in passwords:
        target_hash = sha256_hash(pwd)
        result      = dictionary_attack(target_hash)
        result["original_password"] = pwd
        result["hash"]              = target_hash
        results.append(result)
    return results
