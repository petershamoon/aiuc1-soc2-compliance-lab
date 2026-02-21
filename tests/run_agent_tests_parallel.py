#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Parallel Agent Test Runner
# ---------------------------------------------------------------------------
# Runs all 4 agent functional tests concurrently using threading to work
# around per-agent queue latency on Azure AI Foundry.
# ---------------------------------------------------------------------------

import sys
import os
import json
import time
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import (
    FoundryClient, FunctionClient, AgentRunner,
    AGENT_SERVICE_ENDPOINT, AGENT_SERVICE_API_KEY, AGENT_API_VERSION,
    FUNCTIONS_BASE_URL, FUNCTIONS_HOST_KEY
)

AGENT_IDS = {
    "SOC 2 Auditor":      "asst_BOcJaJfhBCqSEZYvdulpMIpL",
    "Evidence Collector": "asst_SZannksREqz3xf16npVTr473",
    "Policy Writer":      "asst_WgvcIDM24qQLeJ3Dea97u3Hr",
    "IaC Deployer":       "asst_B6b8AgGJEtOj1gSpiYTczqXL",
}

AGENT_PROMPTS = {
    "SOC 2 Auditor": (
        "Perform a CC6 compliance scan of the rg-production resource group. "
        "Check NSG rules and RBAC assignments for any access control violations. "
        "Summarize your findings."
    ),
    "Evidence Collector": (
        "Collect technical evidence for CC6.1 (Logical Access Controls). "
        "Focus on NSG rules in rg-production. Validate the evidence and summarize."
    ),
    "Policy Writer": (
        "Draft a 'Network Access Control Policy' for our Azure environment. "
        "Query current policy compliance state, then write a policy addressing gaps. "
        "Include SOC 2 CC6 criteria references."
    ),
    "IaC Deployer": (
        "I need to remediate the open RDP rule on prod-open-nsg. "
        "Please run a terraform plan to show what changes would be made "
        "to restrict inbound RDP access. Do not apply any changes yet."
    ),
}

results = {}
lock = threading.Lock()


def run_agent(name, agent_id, prompt):
    foundry = FoundryClient(AGENT_SERVICE_ENDPOINT, AGENT_SERVICE_API_KEY, AGENT_API_VERSION)
    functions = FunctionClient(FUNCTIONS_BASE_URL, FUNCTIONS_HOST_KEY)
    runner = AgentRunner(foundry, functions)

    start = time.time()
    result = runner.run(assistant_id=agent_id, prompt=prompt, max_wait=180)
    elapsed = time.time() - start

    with lock:
        results[name] = {
            "status": result.status,
            "tools_called": result.tool_names,
            "message_length": len(result.final_message),
            "message_preview": result.final_message[:500],
            "elapsed_seconds": round(elapsed, 1),
            "error": result.error,
        }
        print(f"[{name}] Done in {elapsed:.0f}s — status={result.status} tools={result.tool_names}")


def main():
    print(f"Starting parallel agent tests at {datetime.now(timezone.utc).isoformat()}")
    print(f"Running {len(AGENT_IDS)} agents concurrently...")
    print()

    threads = []
    for name, agent_id in AGENT_IDS.items():
        t = threading.Thread(target=run_agent, args=(name, agent_id, AGENT_PROMPTS[name]))
        t.start()
        threads.append(t)
        time.sleep(1)  # Stagger start times slightly

    for t in threads:
        t.join()

    print()
    print("=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    for name, r in results.items():
        status_icon = "✓" if r["status"] == "completed" else "✗"
        print(f"{status_icon} {name}: {r['status']} | tools={r['tools_called']} | {r['elapsed_seconds']}s")
        if r["error"]:
            print(f"  Error: {r['error']}")

    # Save results
    output_path = os.path.join(os.path.dirname(__file__), "results", "agent_run_results.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agents": results
        }, f, indent=2)
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
