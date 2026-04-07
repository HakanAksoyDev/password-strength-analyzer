"""
hasher.py — Local Password Hashing Module

Demonstrates safe password storage using SHA-256 (for illustration) and
bcrypt (the production-quality choice).  All operations are LOCAL only.

IMPORTANT: SHA-256 without salting is shown here ONLY to explain why it is
insecure.  Always use bcrypt / argon2 / scrypt in real applications.
"""

import hashlib
import os
import hmac

try:
    import bcrypt as _bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


# ---------------------------------------------------------------------------
# SHA-256 helpers (educational — NOT for production use)
# ---------------------------------------------------------------------------

def sha256_hash(password: str) -> str:
    """Return the hex SHA-256 digest of a password (no salt — insecure demo).

    ⚠  Educational use ONLY.  SHA-256 is NOT a suitable password-hashing
    function in production because it is too fast — attackers can compute
    billions of hashes per second.  Use bcrypt, argon2, or scrypt instead.
    """
    # nosec B324 — intentionally insecure for educational demonstration
    return hashlib.sha256(password.encode("utf-8")).hexdigest()  # nosec


def sha256_hash_with_salt(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """
    Hash a password with a random salt using SHA-256.

    Returns:
        (hex_hash, hex_salt) — both as hex strings for easy display.

    Note: Still not recommended for production.  Use bcrypt/argon2 instead.
    """
    if salt is None:
        salt = os.urandom(16)
    salted = salt + password.encode("utf-8")
    digest = hashlib.sha256(salted).hexdigest()  # nosec — educational demo only
    return digest, salt.hex()


def verify_sha256_salted(password: str, hex_hash: str, hex_salt: str) -> bool:
    """Verify a password against a salted SHA-256 hash."""
    salt    = bytes.fromhex(hex_salt)
    digest, _ = sha256_hash_with_salt(password, salt)
    # Use hmac.compare_digest to prevent timing attacks
    return hmac.compare_digest(digest, hex_hash)


# ---------------------------------------------------------------------------
# bcrypt helpers (recommended for production demos)
# ---------------------------------------------------------------------------

def bcrypt_hash(password: str) -> bytes | None:
    """
    Hash a password with bcrypt (work factor = 12).
    Returns None if bcrypt is not installed.
    """
    if not BCRYPT_AVAILABLE:
        return None
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt(rounds=12))


def bcrypt_verify(password: str, hashed: bytes) -> bool:
    """Verify a password against a bcrypt hash."""
    if not BCRYPT_AVAILABLE:
        raise RuntimeError("bcrypt is not installed.  Run: pip install bcrypt")
    return _bcrypt.checkpw(password.encode("utf-8"), hashed)


# ---------------------------------------------------------------------------
# Convenience: build a small local "database" for demos
# ---------------------------------------------------------------------------

def build_local_hash_db(passwords: list[str], method: str = "sha256_salted") -> dict:
    """
    Create a local dict mapping password → stored hash entry.

    Args:
        passwords: List of plaintext passwords.
        method:    "sha256"        — unsalted SHA-256 (purely educational)
                   "sha256_salted" — salted SHA-256
                   "bcrypt"        — bcrypt (requires bcrypt package)

    Returns:
        Dict with keys being passwords and values being hash info dicts.
    """
    db = {}
    for pwd in passwords:
        if method == "sha256":
            db[pwd] = {
                "method": "sha256",
                "hash":   sha256_hash(pwd),
                "salt":   None,
            }
        elif method == "sha256_salted":
            h, s = sha256_hash_with_salt(pwd)
            db[pwd] = {
                "method": "sha256_salted",
                "hash":   h,
                "salt":   s,
            }
        elif method == "bcrypt":
            h = bcrypt_hash(pwd)
            db[pwd] = {
                "method": "bcrypt",
                "hash":   h,
                "salt":   None,   # bcrypt embeds salt in the hash
            }
        else:
            raise ValueError(f"Unknown hashing method: {method}")
    return db
