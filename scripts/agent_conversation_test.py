#!/usr/bin/env python3
"""
AIUC-1 SOC 2 Compliance Lab — Agent Conversation Test
======================================================
Exercises the registered Azure AI Foundry agent through a series of
single-turn conversations that test its ability to use the 12 GRC tools.

Uses the azure-ai-agents SDK's create_thread_and_process_run() method
which handles thread creation, message sending, tool execution, and
polling in a single call.

Usage:
    source .env
    python3 scripts/agent_conversation_test.py
"""

import json
import os
import sys
import time
from datetime import datetime

# Force unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

from azure.ai.agents import AgentsClient
from azure.ai.agents.models import (
    AgentThreadCreationOptions,
    ThreadMessageOptions,
)
from azure.identity import ClientSecretCredential


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AGENT_ID = "<YOUR-AGENT-ID>"
FOUNDRY_ENDPOINT = os.environ.get("AZURE_FOUNDRY_ENDPOINT", "")
PROJECT_ENDPOINT = f"{FOUNDRY_ENDPOINT}/api/projects/<REDACTED-PROJECT>"
TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

# Test prompts — each exercises one or more tools
TEST_PROMPTS = [
    {
        "name": "CC6 Gap Analysis",
        "prompt": "Perform a gap analysis for CC6 (Logical and Physical Access Controls). What gaps exist in our Azure environment?",
        "expected_tools": ["gap_analyzer"],
    },
    {
        "name": "CC6 Resource Scan",
        "prompt": "Scan our Azure environment for CC6 criteria. Show me what resources are in scope and their compliance status.",
        "expected_tools": ["scan_cc_criteria"],
    },
    {
        "name": "Access Controls Query",
        "prompt": "Query the access controls for our production resource group (rg-production). Show RBAC assignments and NSG rules.",
        "expected_tools": ["query_access_controls"],
    },
    {
        "name": "Defender Score",
        "prompt": "What is our current Microsoft Defender secure score? Include the top security assessments.",
        "expected_tools": ["query_defender_score"],
    },
    {
        "name": "Policy Compliance",
        "prompt": "Check our Azure Policy compliance status. Are there any non-compliant policies?",
        "expected_tools": ["query_policy_compliance"],
    },
    {
        "name": "Generate POA&M",
        "prompt": "Generate a POA&M entry for finding CC6-NSG-001: NSG prod-open-nsg in resource group rg-production allows RDP from any source. CC category is CC6, severity is high. The resource is Microsoft.Network/networkSecurityGroups/prod-open-nsg. Remediation plan: restrict RDP source to 10.0.0.0/8 via Terraform.",
        "expected_tools": ["generate_poam_entry"],
    },
    {
        "name": "Sanitize Output",
        "prompt": "Sanitize this text: 'The subscription ID is 00000000-0000-0000-0000-000000000000 and the server IP is 10.0.1.5'",
        "expected_tools": ["sanitize_output"],
    },
]


def run_single_turn(client, test, turn_num, total):
    """Run a single-turn conversation with the agent."""
    print(f"\n{'─'*70}")
    print(f"  Turn {turn_num}/{total}: {test['name']}")
    print(f"  Prompt: {test['prompt'][:80]}...")
    print(f"{'─'*70}")

    start = time.time()

    try:
        # Create thread with message and run agent in one call
        thread_opts = AgentThreadCreationOptions(
            messages=[
                ThreadMessageOptions(
                    role="user",
                    content=test["prompt"],
                )
            ]
        )

        run = client.create_thread_and_process_run(
            agent_id=AGENT_ID,
            thread=thread_opts,
            polling_interval=3,
        )

        elapsed = time.time() - start
        print(f"    Status: {run.status} ({elapsed:.1f}s)")

        # Extract response from the thread using sub-operations
        response_text = ""
        tool_calls = []

        if str(run.status) == "RunStatus.COMPLETED":
            # Get messages using the messages sub-operation
            msgs = list(client.messages.list(thread_id=run.thread_id))
            for msg in msgs:
                if msg.role == "assistant":
                    for block in msg.content:
                        if hasattr(block, "text"):
                            response_text = block.text.value
                            break
                    break

            # Get run steps to see tool calls
            try:
                steps = list(client.run_steps.list(
                    thread_id=run.thread_id,
                    run_id=run.id,
                ))
                for step in steps:
                    if hasattr(step, "step_details") and hasattr(step.step_details, "tool_calls"):
                        for tc in step.step_details.tool_calls:
                            if hasattr(tc, "azure_function"):
                                tool_calls.append(tc.azure_function.name)
                            elif hasattr(tc, "function"):
                                tool_calls.append(tc.function.name)
                            else:
                                tool_calls.append(str(getattr(tc, "type", "unknown")))
            except Exception as e:
                print(f"    (Could not retrieve run steps: {e})")

        elif str(run.status) == "RunStatus.FAILED":
            error_msg = ""
            if hasattr(run, "last_error") and run.last_error:
                error_msg = str(run.last_error)
            print(f"    Error: {error_msg[:200]}")

        print(f"    Tools called: {tool_calls if tool_calls else 'none detected'}")
        if response_text:
            # Truncate for display
            preview = response_text[:200].replace("\n", " ")
            print(f"    Response preview: {preview}...")

        return {
            "turn": turn_num,
            "name": test["name"],
            "status": str(run.status),
            "elapsed_seconds": round(elapsed, 1),
            "tools_called": tool_calls,
            "expected_tools": test["expected_tools"],
            "response_length": len(response_text),
            "response_preview": response_text[:500],
            "thread_id": run.thread_id,
            "run_id": run.id,
        }

    except Exception as e:
        elapsed = time.time() - start
        print(f"    EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        return {
            "turn": turn_num,
            "name": test["name"],
            "status": "exception",
            "elapsed_seconds": round(elapsed, 1),
            "tools_called": [],
            "expected_tools": test["expected_tools"],
            "response_length": 0,
            "response_preview": str(e)[:500],
            "thread_id": "",
            "run_id": "",
        }


def main():
    if not all([FOUNDRY_ENDPOINT, TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("ERROR: Missing required environment variables")
        sys.exit(1)

    credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )

    client = AgentsClient(
        endpoint=PROJECT_ENDPOINT,
        credential=credential,
    )

    print(f"{'='*70}")
    print(f"  AIUC-1 Agent Conversation Test")
    print(f"  Agent ID: {AGENT_ID}")
    print(f"  Endpoint: {PROJECT_ENDPOINT}")
    print(f"  Time:     {datetime.utcnow().isoformat()}")
    print(f"{'='*70}")

    # Verify agent exists
    agent = client.get_agent(agent_id=AGENT_ID)
    print(f"  Agent verified: {agent.name} ({len(agent.tools)} tools)")

    results = []
    total = len(TEST_PROMPTS)

    for i, test in enumerate(TEST_PROMPTS, 1):
        result = run_single_turn(client, test, i, total)
        results.append(result)

    # Summary
    print(f"\n{'='*70}")
    print(f"  AGENT CONVERSATION TEST SUMMARY")
    print(f"{'='*70}")

    completed = sum(1 for r in results if "COMPLETED" in r["status"].upper())
    for r in results:
        icon = "✓" if "COMPLETED" in r["status"].upper() else "✗"
        tools = ", ".join(r["tools_called"]) if r["tools_called"] else "none"
        print(f"  {icon} Turn {r['turn']}: {r['name']:25s} status={r['status']:30s} tools=[{tools}] ({r['elapsed_seconds']}s)")

    print(f"\n  Completed: {completed}/{len(results)}")

    # Save results
    evidence_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "evidence",
        "agent_conversation_results.json",
    )
    with open(evidence_path, "w") as f:
        json.dump(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "agent_id": AGENT_ID,
                "agent_name": agent.name,
                "turns": results,
                "summary": {
                    "total": len(results),
                    "completed": completed,
                    "failed": len(results) - completed,
                },
            },
            f,
            indent=2,
        )
    print(f"  Results saved to {evidence_path}")

    return 0 if completed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
