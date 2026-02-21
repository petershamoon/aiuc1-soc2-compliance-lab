#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5 Test Runner
# ---------------------------------------------------------------------------
# Standalone script that executes the full test suite, captures results,
# and writes a structured JSON results file for the report generator.
#
# Usage:
#   python3 tests/run_tests.py
#
# Output:
#   tests/results/test_results.json  — machine-readable results
#   tests/results/test_output.txt    — full pytest output
# ---------------------------------------------------------------------------

import subprocess
import sys
import os
import json
from datetime import datetime, timezone

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(TESTS_DIR, "results")
REPO_ROOT = os.path.dirname(TESTS_DIR)


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    json_report_path = os.path.join(RESULTS_DIR, "test_results.json")
    txt_output_path = os.path.join(RESULTS_DIR, "test_output.txt")

    print("=" * 70)
    print("AIUC-1 SOC 2 Compliance Lab — Phase 5 Test Suite")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print()

    # Run pytest with JSON report plugin
    cmd = [
        sys.executable, "-m", "pytest",
        TESTS_DIR,
        "--ignore", os.path.join(TESTS_DIR, "run_tests.py"),
        "-v",
        "--tb=short",
        "--json-report",
        f"--json-report-file={json_report_path}",
        "--json-report-indent=2",
        "-p", "no:warnings",
    ]

    print(f"Running: {' '.join(cmd)}")
    print()

    with open(txt_output_path, "w") as out_file:
        result = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out_file.write(result.stdout)
        print(result.stdout)

    print()
    print("=" * 70)
    print(f"Exit code: {result.returncode}")
    print(f"Results JSON: {json_report_path}")
    print(f"Output log:   {txt_output_path}")
    print("=" * 70)

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
