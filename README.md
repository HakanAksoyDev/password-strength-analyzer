# Password Security Lab 🔐
### Password Strength Analyzer and Controlled Password Cracking Demonstration

> **Academic project for a Computer Security course.**  
> All demonstrations are LOCAL ONLY and use locally generated test data.  
> Do NOT use any part of this code against real accounts or systems.

---

## Project Overview

This project studies password security through two complementary tools:

1. **Password Strength Analyzer** — evaluates a password and explains *why* it is weak or strong.
2. **Controlled Cracking Demo** — shows, in a safe classroom environment, how brute-force and dictionary attacks work on locally generated hashes.

---

## Folder Structure

```
password-strength-analyzer/
├── main.py                          # Main entry point (CLI)
├── requirements.txt                 # Python dependencies
├── README.md
├── src/
│   ├── __init__.py
│   ├── analyzer.py                  # Password strength analyzer
│   ├── dictionary_checker.py        # Common-password & wordlist checker
│   ├── password_generator.py        # Sample password generator
│   ├── hasher.py                    # SHA-256 / bcrypt hashing helpers
│   ├── brute_force.py               # Brute-force attack demo (≤6 chars)
│   ├── dictionary_attack.py         # Dictionary attack demo
│   └── logger.py                    # Console & file result logger
├── data/
│   ├── common_passwords.txt         # List of well-known weak passwords
│   └── wordlist.txt                 # English dictionary wordlist
└── experiments/
    └── run_experiments.py           # Full experiment suite
```

---

## Requirements

- Python 3.10+
- `bcrypt` (optional — only required for bcrypt hashing demo)

```bash
pip install -r requirements.txt
```

---

## Quick Start

### Interactive Mode (default)
```bash
python main.py
```
Type any password and get an instant strength report.

### Analyze a Single Password
```bash
python main.py --analyze "MyP@ssw0rd!"
```

### Run the Full Experiment Demo
```bash
python main.py --demo
# or
python experiments/run_experiments.py
```

### Dictionary Attack Demo (educational)
```bash
python main.py --crack "password"
```

### Brute-Force Demo (educational, ≤ 6 characters only)
```bash
python main.py --brute "abc"
```

---

## How the Analyzer Works

The analyzer scores a password from **0 to 100** across five dimensions:

| Dimension         | Max Points | What it measures                              |
|-------------------|-----------|-----------------------------------------------|
| Length            | 30        | Longer passwords are exponentially harder to crack |
| Diversity         | 25        | Mix of lower, upper, digits, symbols           |
| Entropy           | 20        | Shannon-like bits of randomness                |
| Pattern penalty   | 15        | Deducted for `abc`, `123`, `qwerty`, repeats  |
| Dictionary penalty| 10        | Deducted for common/dictionary passwords       |

**Strength labels:**

| Score  | Label       |
|--------|-------------|
| 0–19   | Very Weak   |
| 20–39  | Weak        |
| 40–59  | Medium      |
| 60–79  | Strong      |
| 80–100 | Very Strong |

---

## Sample Output

```
  Password : 'password'
  Score    : 3/100
  Strength : Very Weak
  Entropy  : 37.6 bits (charset size ≈ 26)
  Reasons  :
    • Password is too short (8 characters).
    • Missing character types: uppercase letters, digits, special characters.
    • Estimated entropy: 37.6 bits (charset size ≈ 26).
    • This is a well-known common password — very easy to guess.
  Suggestions :
    → Use at least 8 characters; 12+ is recommended.
    → Add uppercase letters, digits, special characters (e.g. !@#$) to increase complexity.
    → Avoid dictionary words, common passwords, and simple substitutions.
```

---

## Ethical Statement

This project is created for **educational purposes only** within a controlled academic setting.

- ✅ All attacks run against **locally generated, sample hashes only**.
- ✅ No real user accounts, databases, or online services are targeted.
- ✅ The brute-force demo is intentionally limited to **≤ 6 characters**.
- ❌ Do NOT use this code against any system without explicit written permission.
- ❌ Unauthorized password cracking is **illegal** in most jurisdictions.

---

## Modules

| Module | Purpose |
|--------|---------|
| `analyzer.py` | Core strength scoring logic |
| `dictionary_checker.py` | Loads and queries password/word lists |
| `password_generator.py` | Provides sample passwords for testing |
| `hasher.py` | SHA-256 and bcrypt hashing helpers |
| `brute_force.py` | Exhaustive brute-force demo (safety-capped) |
| `dictionary_attack.py` | Wordlist-based offline attack demo |
| `logger.py` | Formatted console output and file logging |

---

## License

For academic and educational use only.