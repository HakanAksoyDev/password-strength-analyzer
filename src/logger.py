"""
logger.py — Results / Experiment Logger

Provides helper functions to:
  - format and print results to the console in a readable table
  - write results to a plain-text log file for report inclusion
"""

import os
import datetime


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

_SEP = "=" * 72


def print_header(title: str) -> None:
    """Print a section header to the console."""
    print(f"\n{_SEP}")
    print(f"  {title}")
    print(_SEP)


def print_analysis_result(password: str, result: dict) -> None:
    """Pretty-print a single password analysis result."""
    print(f"\n  Password : {password!r}")
    print(f"  Score    : {result['score']}/100")
    print(f"  Strength : {result['label']}")
    print(f"  Entropy  : {result['details'].get('entropy_bits', 'N/A')} bits")
    print("  Reasons  :")
    for r in result["reasons"]:
        print(f"    • {r}")
    if result["suggestions"]:
        print("  Suggestions :")
        for s in result["suggestions"]:
            print(f"    → {s}")


def print_attack_result(result: dict, attack_type: str = "Attack") -> None:
    """Pretty-print a single attack result."""
    pwd = result.get("original_password", "?")
    print(f"\n  Password : {pwd!r}")
    print(f"  Hash     : {str(result.get('hash', ''))[:20]}…")
    status = "✓ CRACKED" if result["found"] else "✗ Not found"
    print(f"  Result   : {status}")
    if result["found"]:
        print(f"  Cracked  : {result['password']!r}")
    print(f"  Attempts : {result['attempts']:,}")
    print(f"  Time     : {result['time_sec']:.4f} s")


def print_experiment_table(rows: list[dict]) -> None:
    """
    Print a summary table for multiple experiment results.

    Each row dict should have keys:
        password, score, label, found, attempts, time_sec
    """
    col_w = [20, 7, 12, 8, 12, 10]
    headers = ["Password", "Score", "Strength", "Cracked", "Attempts", "Time (s)"]
    header_line = "  " + "  ".join(
        h.ljust(w) for h, w in zip(headers, col_w)
    )
    sep = "  " + "-" * (sum(col_w) + len(col_w) * 2)

    print(f"\n{sep}")
    print(header_line)
    print(sep)

    for row in rows:
        cracked = "Yes" if row.get("found") else "No"
        line = "  " + "  ".join([
            str(row.get("password", "")).ljust(col_w[0]),
            str(row.get("score",    "")).ljust(col_w[1]),
            str(row.get("label",    "")).ljust(col_w[2]),
            cracked.ljust(col_w[3]),
            str(row.get("attempts", "")).ljust(col_w[4]),
            str(row.get("time_sec", "")).ljust(col_w[5]),
        ])
        print(line)
    print(sep)


# ---------------------------------------------------------------------------
# File logger
# ---------------------------------------------------------------------------

def save_results(
    data:     list[dict],
    filename: str = "experiment_log.txt",
    mode:     str = "a",
) -> str:
    """
    Append or write experiment results to a plain-text log file.

    Args:
        data:     List of result dicts to serialize.
        filename: Output file path (relative to CWD or absolute).
        mode:     File open mode ('a' to append, 'w' to overwrite).

    Returns:
        Absolute path to the written file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"\n{'='*72}", f"Experiment Log — {timestamp}", f"{'='*72}"]

    for entry in data:
        lines.append("")
        for key, value in entry.items():
            lines.append(f"  {key}: {value}")

    lines.append("")

    abs_path = os.path.abspath(filename)
    with open(abs_path, mode, encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return abs_path
