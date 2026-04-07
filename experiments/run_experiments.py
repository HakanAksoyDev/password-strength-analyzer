"""
run_experiments.py — Experimental Setup Script

Runs the full experiment suite:
  1. Analyzes sample passwords across all strength categories.
  2. Runs a dictionary attack on weak/medium passwords.
  3. Runs a brute-force attack on very short passwords.
  4. Prints a summary table and saves results to a log file.

Run from the project root:
    python experiments/run_experiments.py
"""

import sys
import os

# Ensure the project root is on the Python path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzer           import analyze
from src.password_generator import SAMPLE_PASSWORDS
from src.dictionary_attack  import demo_dictionary_attack
from src.brute_force        import demo_brute_force
from src.logger             import (
    print_header,
    print_analysis_result,
    print_attack_result,
    print_experiment_table,
    save_results,
)


# ---------------------------------------------------------------------------
# Experiment 1 — Password Strength Analysis
# ---------------------------------------------------------------------------

def experiment_strength_analysis() -> list[dict]:
    """Analyze all sample passwords and return summary rows."""
    print_header("EXPERIMENT 1 — Password Strength Analysis")

    rows = []
    for category, passwords in SAMPLE_PASSWORDS.items():
        print(f"\n  Category: {category.replace('_', ' ').title()}")
        print("  " + "-" * 50)
        for pwd in passwords:
            result = analyze(pwd)
            print_analysis_result(pwd, result)
            rows.append({
                "password":  pwd,
                "category":  category,
                "score":     result["score"],
                "label":     result["label"],
                "entropy":   result["details"].get("entropy_bits"),
                "found":     None,
                "attempts":  None,
                "time_sec":  None,
            })
    return rows


# ---------------------------------------------------------------------------
# Experiment 2 — Dictionary Attack Demo
# ---------------------------------------------------------------------------

def experiment_dictionary_attack() -> list[dict]:
    """Run dictionary attack on weak and medium passwords."""
    print_header("EXPERIMENT 2 — Dictionary Attack Demo")
    print("  ⚠  Educational demo only — local hashes, no real accounts.\n")

    targets = (
        SAMPLE_PASSWORDS["very_weak"]
        + SAMPLE_PASSWORDS["weak"]
        + SAMPLE_PASSWORDS["medium"][:2]    # include a couple of medium ones
    )
    results = demo_dictionary_attack(targets)

    rows = []
    for r in results:
        print_attack_result(r, attack_type="Dictionary")
        analysis = analyze(r["original_password"])
        rows.append({
            "password":  r["original_password"],
            "score":     analysis["score"],
            "label":     analysis["label"],
            "found":     r["found"],
            "attempts":  r["attempts"],
            "time_sec":  r["time_sec"],
        })
    return rows


# ---------------------------------------------------------------------------
# Experiment 3 — Brute-Force Attack Demo
# ---------------------------------------------------------------------------

def experiment_brute_force() -> list[dict]:
    """Run brute-force attack on very short passwords only."""
    print_header("EXPERIMENT 3 — Brute-Force Attack Demo (≤ 4 chars)")
    print("  ⚠  Educational demo only — limited to 4-character passwords.\n")

    # Use only the very short very_weak samples for brute force
    targets = SAMPLE_PASSWORDS["very_weak"]  # all ≤ 6 chars
    results = demo_brute_force(targets, max_length=4)

    rows = []
    for r in results:
        print_attack_result(r, attack_type="Brute Force")
        analysis = analyze(r["original_password"])
        rows.append({
            "password":  r["original_password"],
            "score":     analysis["score"],
            "label":     analysis["label"],
            "found":     r["found"],
            "attempts":  r["attempts"],
            "time_sec":  r["time_sec"],
        })
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 72)
    print("  PASSWORD SECURITY LAB — Experiment Runner")
    print("  Academic demo | Local environment only")
    print("=" * 72)

    analysis_rows = experiment_strength_analysis()
    dict_rows     = experiment_dictionary_attack()
    bf_rows       = experiment_brute_force()

    # --- Summary table for attack experiments ---
    print_header("SUMMARY TABLE — Attack Results")
    all_attack_rows = dict_rows + bf_rows
    print_experiment_table(all_attack_rows)

    # --- Save to log file ---
    log_path = save_results(
        analysis_rows + all_attack_rows,
        filename="experiment_log.txt",
        mode="w",
    )
    print(f"\n  Results saved to: {log_path}\n")


if __name__ == "__main__":
    main()
