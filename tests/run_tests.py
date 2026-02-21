#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Phase 5: Main Test Runner (DB-enabled)
# ---------------------------------------------------------------------------
import pytest
import os
import sys

def main():
    # Load connection string from the file created during provisioning
    # This makes the DB connection available to the pytest fixtures
    try:
        with open("/tmp/test_results_env.txt") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    os.environ[key] = value
        print("INFO: Database connection string loaded into environment.")
    except FileNotFoundError:
        print("WARN: /tmp/test_results_env.txt not found. Database logging will be skipped.")

    # Define test modules to run in order
    test_files = [
        "tests/test_integration.py",
        "tests/test_control_enforcement.py",
        "tests/test_hallucination_prevention.py",
        "tests/test_agent_functionality.py",
    ]

    exit_code = 0
    for test_file in test_files:
        print(f"\n{'='*25} RUNNING: {os.path.basename(test_file)} {'='*25}\n")
        # The result_recorder fixture in conftest.py handles writing to the database.
        # We still generate JSON reports for a secondary, human-readable summary.
        report_path = os.path.join("tests", "results", f"pytest_{os.path.basename(test_file).replace('test_', '')}.json")
        ret = pytest.main(["-v", test_file, f"--json-report-file={report_path}"])
        if ret != 0:
            print(f"ERROR: {test_file} failed with exit code {ret}")
            exit_code = 1 # Propagate failure

    print(f"\n{'='*25} RUNNING: Agent Validation {'='*25}\n")
    # The agent validation runner has its own DB writing logic.
    try:
        # Ensure the module is importable
        sys.path.insert(0, os.path.dirname(__file__))
        import run_agent_validation
        run_agent_validation.main()
        print("INFO: Agent validation completed.")
    except Exception as e:
        print(f"ERROR: Agent validation runner failed: {e}")
        exit_code = 1

    print(f"\n{'='*25} TEST RUN COMPLETE {'='*25}\n")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
