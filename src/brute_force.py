"""
brute_force.py — Brute Force Attack Demonstration Module

⚠️  ETHICAL WARNING ⚠️
This module is provided SOLELY for educational purposes in a controlled,
local environment.  It demonstrates why short, simple passwords are
dangerously weak.  Do NOT use this code to attack real accounts, systems,
or any hash obtained without explicit written permission.

The demo is intentionally limited to passwords ≤ 6 characters so the
runtime stays short enough for a classroom demonstration.
"""

import itertools
import string
import time

from src.hasher import sha256_hash

# ---------------------------------------------------------------------------
# Safety guard — refuse to attempt passwords longer than this limit
# ---------------------------------------------------------------------------
MAX_ALLOWED_LENGTH = 6


def brute_force_attack(
    target_hash:  str,
    charset:      str  = string.ascii_lowercase + string.digits,
    max_length:   int  = 4,
    verbose:      bool = False,
) -> dict:
    """
    Attempt to crack a SHA-256 hash by exhaustive brute force.

    Args:
        target_hash: Hex SHA-256 digest of the target password.
        charset:     Characters to try (default: lowercase + digits).
        max_length:  Maximum password length to try (capped at MAX_ALLOWED_LENGTH).
        verbose:     Print each attempt if True (very slow for long passwords).

    Returns:
        {
            "found":    bool,
            "password": str | None,
            "attempts": int,
            "time_sec": float,
        }
    """
    # Enforce safety cap
    max_length = min(max_length, MAX_ALLOWED_LENGTH)

    start     = time.perf_counter()
    attempts  = 0
    found_pwd = None

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if verbose:
                print(f"  Trying: {candidate}", end="\r")
            if sha256_hash(candidate) == target_hash:
                found_pwd = candidate
                elapsed   = time.perf_counter() - start
                return {
                    "found":    True,
                    "password": found_pwd,
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


def demo_brute_force(passwords: list[str], max_length: int = 4) -> list[dict]:
    """
    Run a brute-force demo on a list of plaintext passwords.

    For each password:
      1. Hash it with SHA-256.
      2. Try to crack the hash by brute force.
      3. Collect and return results.

    Args:
        passwords:  List of plaintext passwords to demo.
        max_length: Maximum length to try (must be ≤ MAX_ALLOWED_LENGTH).

    Returns:
        List of result dicts (one per password).
    """
    max_length = min(max_length, MAX_ALLOWED_LENGTH)
    results    = []

    for pwd in passwords:
        target_hash = sha256_hash(pwd)
        result      = brute_force_attack(target_hash, max_length=max_length)
        result["original_password"] = pwd
        result["hash"]              = target_hash
        results.append(result)

    return results
