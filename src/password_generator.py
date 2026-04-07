"""
password_generator.py — Sample Password Generator for Test Cases

Provides ready-made sample passwords across five strength categories and a
function to generate random passwords of a given character profile.
"""

import random
import string


# ---------------------------------------------------------------------------
# Pre-defined sample passwords for experiments
# ---------------------------------------------------------------------------
SAMPLE_PASSWORDS = {
    "very_weak": [
        "123",
        "abc",
        "1234",
        "pass",
        "qwerty",
    ],
    "weak": [
        "password",
        "letmein",
        "12345678",
        "iloveyou",
        "monkey123",
    ],
    "medium": [
        "Welcome1",
        "Summer2023",
        "Banana99!",
        "MyDog2024",
        "Hello$World",
    ],
    "strong": [
        "Tr0ub4dor&3",
        "correct#Horse7",
        "P@ssw0rd!99",
        "Dragon$Fly42!",
        "Sunsh1ne#Rain",
    ],
    "very_strong": [
        "X#9mK!vQ2@nL",
        "3$Gp!zW8qR#mN",
        "kT!9@xLm#2Wv$",
        "!Qz4%Yr8&Jn2Kp",
        "mN3#pV!7@tX2$cZ",
    ],
}


def generate_random_password(
    length:     int  = 12,
    use_lower:  bool = True,
    use_upper:  bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a random password with the specified character classes.

    Args:
        length:      Desired password length.
        use_lower:   Include lowercase letters.
        use_upper:   Include uppercase letters.
        use_digits:  Include digits.
        use_symbols: Include special characters.

    Returns:
        A random password string.
    """
    charset = ""
    mandatory = []          # Ensure at least one char from each selected class

    if use_lower:
        charset  += string.ascii_lowercase
        mandatory += [random.choice(string.ascii_lowercase)]
    if use_upper:
        charset  += string.ascii_uppercase
        mandatory += [random.choice(string.ascii_uppercase)]
    if use_digits:
        charset  += string.digits
        mandatory += [random.choice(string.digits)]
    if use_symbols:
        symbols   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        charset  += symbols
        mandatory += [random.choice(symbols)]

    if not charset:
        raise ValueError("At least one character class must be selected.")

    # Ensure requested length is at least the number of mandatory characters
    num_mandatory = len(mandatory)
    if length < num_mandatory:
        length = num_mandatory

    remaining = [random.choice(charset) for _ in range(length - num_mandatory)]
    password_chars = mandatory + remaining
    random.shuffle(password_chars)
    return "".join(password_chars)


def get_all_samples() -> list[tuple[str, str]]:
    """Return all (category, password) pairs as a flat list."""
    pairs = []
    for category, passwords in SAMPLE_PASSWORDS.items():
        for pwd in passwords:
            pairs.append((category, pwd))
    return pairs
