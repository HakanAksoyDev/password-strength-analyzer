"""
main.py — Password Security Lab: Main Entry Point

Usage:
    python main.py                        # Interactive mode
    python main.py --analyze "MyP@ss1!"  # Analyze a single password
    python main.py --demo                 # Run the full experiment demo
    python main.py --crack "password"    # Dictionary attack on one password
    python main.py --brute "abc"         # Brute-force on one short password

⚠  ETHICAL WARNING ⚠
This tool is for EDUCATIONAL and ACADEMIC PURPOSES ONLY.
All cracking demonstrations use locally generated hashes.
Do NOT use any part of this code against real systems or accounts.
"""

import argparse
import sys
import os

# Allow running from the project root directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.analyzer          import analyze
from src.dictionary_attack import dictionary_attack
from src.brute_force       import brute_force_attack, MAX_ALLOWED_LENGTH
from src.hasher            import sha256_hash
from src.logger            import (
    print_header,
    print_analysis_result,
    print_attack_result,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strength_bar(score: int, width: int = 20) -> str:
    """Return an ASCII progress bar representing the password score."""
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {score}/100"


def _label_color(label: str) -> str:
    """Return ANSI-colored label string (falls back gracefully on Windows)."""
    colors = {
        "Very Weak":  "\033[91m",   # red
        "Weak":       "\033[93m",   # yellow
        "Medium":     "\033[94m",   # blue
        "Strong":     "\033[92m",   # green
        "Very Strong":"\033[92m",   # green
    }
    reset  = "\033[0m"
    color  = colors.get(label, "")
    return f"{color}{label}{reset}"


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_mode():
    print("\n" + "=" * 60)
    print("  Password Security Lab — Interactive Analyzer")
    print("  Type 'quit' to exit.")
    print("=" * 60)

    while True:
        try:
            pwd = input("\n  Enter a password to analyze: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye!")
            break

        if pwd.lower() in ("quit", "exit", "q"):
            print("  Goodbye!")
            break

        if not pwd:
            print("  Please enter a non-empty password.")
            continue

        result = analyze(pwd)
        print()
        print(f"  Score    : {_strength_bar(result['score'])}")
        print(f"  Strength : {_label_color(result['label'])}")
        print(f"  Entropy  : {result['details'].get('entropy_bits', 'N/A')} bits")
        print()
        print("  Reasons:")
        for r in result["reasons"]:
            print(f"    • {r}")
        if result["suggestions"]:
            print()
            print("  Suggestions:")
            for s in result["suggestions"]:
                print(f"    → {s}")


# ---------------------------------------------------------------------------
# Single-password analyze
# ---------------------------------------------------------------------------

def cmd_analyze(password: str):
    result = analyze(password)
    print_header(f"Password Analysis: {password!r}")
    print_analysis_result(password, result)
    print(f"\n  [{_strength_bar(result['score'])}]")


# ---------------------------------------------------------------------------
# Dictionary attack on a single password
# ---------------------------------------------------------------------------

def cmd_crack(password: str):
    print_header(f"Dictionary Attack Demo: {password!r}")
    print("  ⚠  Educational demo only — local hashes only.\n")
    target_hash = sha256_hash(password)
    result      = dictionary_attack(target_hash)
    result["original_password"] = password
    result["hash"]              = target_hash
    print_attack_result(result, attack_type="Dictionary")


# ---------------------------------------------------------------------------
# Brute-force attack on a single short password
# ---------------------------------------------------------------------------

def cmd_brute(password: str):
    if len(password) > MAX_ALLOWED_LENGTH:
        print(
            f"\n  ⚠  Brute-force demo is limited to passwords ≤ {MAX_ALLOWED_LENGTH} "
            "characters for safety.  Aborting."
        )
        sys.exit(1)

    print_header(f"Brute-Force Attack Demo: {password!r}")
    print("  ⚠  Educational demo only — local hashes only.\n")
    target_hash = sha256_hash(password)
    result      = brute_force_attack(target_hash, max_length=len(password))
    result["original_password"] = password
    result["hash"]              = target_hash
    print_attack_result(result, attack_type="Brute Force")


# ---------------------------------------------------------------------------
# Full demo (delegates to experiments/run_experiments.py)
# ---------------------------------------------------------------------------

def cmd_demo():
    experiments_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "experiments", "run_experiments.py"
    )
    # Import and run directly instead of subprocess to avoid path issues
    import importlib.util
    spec   = importlib.util.spec_from_file_location("run_experiments", experiments_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Password Security Lab — Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                        # Interactive mode\n"
            "  python main.py --analyze 'MyP@ss1!'  # Analyze a password\n"
            "  python main.py --demo                 # Full experiment demo\n"
            "  python main.py --crack 'password'    # Dictionary attack\n"
            "  python main.py --brute 'abc'         # Brute-force (≤6 chars)\n"
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--analyze", metavar="PASSWORD",
                       help="Analyze strength of a single password.")
    group.add_argument("--demo",    action="store_true",
                       help="Run the full experiment demo.")
    group.add_argument("--crack",   metavar="PASSWORD",
                       help="Dictionary attack on a single password (educational).")
    group.add_argument("--brute",   metavar="PASSWORD",
                       help=f"Brute-force a short password (≤{MAX_ALLOWED_LENGTH} chars, educational).")
    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.analyze:
        cmd_analyze(args.analyze)
    elif args.demo:
        cmd_demo()
    elif args.crack:
        cmd_crack(args.crack)
    elif args.brute:
        cmd_brute(args.brute)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
