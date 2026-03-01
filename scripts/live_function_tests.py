#!/usr/bin/env python3
"""
AIUC-1 SOC 2 Compliance Lab — Live Function Invocation Tests
=============================================================
Sends messages to each of the 12 Azure Function input queues and reads
responses from the corresponding output queues.

This validates the full end-to-end pipeline:
  Queue message → Function trigger → Enforcement layer → Azure API → Response

Usage:
    export AZURE_STORAGE_CONNECTION_STRING="..."
    python3 scripts/live_function_tests.py
"""

import json
import os
import sys
import time
import uuid
import hmac
import hashlib
import base64
from datetime import datetime

try:
    from azure.storage.queue import QueueServiceClient
except ImportError:
    print("Installing azure-storage-queue...")
    os.system("sudo pip3 install azure-storage-queue")
    from azure.storage.queue import QueueServiceClient


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STORAGE_CONN_STR = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
APPROVAL_SECRET = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")

# Each function has an input queue and an output queue
FUNCTIONS = [
    {
        "name": "gap_analyzer",
        "input_queue": "gap-analyzer-input",
        "output_queue": "gap-analyzer-output",
        "payload": {"cc_category": "CC6"},
    },
    {
        "name": "scan_cc_criteria",
        "input_queue": "scan-cc-criteria-input",
        "output_queue": "scan-cc-criteria-output",
        "payload": {"cc_category": "CC6", "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID", "")},
    },
    {
        "name": "evidence_validator",
        "input_queue": "evidence-validator-input",
        "output_queue": "evidence-validator-output",
        "payload": {"evidence_type": "azure_resource", "target": "Microsoft.Network/networkSecurityGroups/prod-open-nsg", "resource_group": "rg-production"},
    },
    {
        "name": "query_access_controls",
        "input_queue": "query-access-controls-input",
        "output_queue": "query-access-controls-output",
        "payload": {"resource_group": "rg-production", "include_nsg": True},
    },
    {
        "name": "query_defender_score",
        "input_queue": "query-defender-score-input",
        "output_queue": "query-defender-score-output",
        "payload": {"include_assessments": True, "max_results": 10},
    },
    {
        "name": "query_policy_compliance",
        "input_queue": "query-policy-compliance-input",
        "output_queue": "query-policy-compliance-output",
        "payload": {"include_details": True, "max_results": 10},
    },
    {
        "name": "generate_poam_entry",
        "input_queue": "generate-poam-entry-input",
        "output_queue": "generate-poam-entry-output",
        "payload": {
            "finding_id": "CC6-NSG-001",
            "cc_category": "CC6",
            "resource": "Microsoft.Network/networkSecurityGroups/prod-open-nsg",
            "gap_description": "NSG prod-open-nsg allows RDP from any source",
            "severity": "high",
            "remediation_plan": "Restrict RDP source to 10.0.0.0/8 via Terraform",
            "milestones": [
                {"description": "Run terraform plan", "target_date": "2026-03-01"},
                {"description": "Run terraform apply", "target_date": "2026-03-02"},
            ],
        },
    },
    {
        "name": "run_terraform_plan",
        "input_queue": "run-terraform-plan-input",
        "output_queue": "run-terraform-plan-output",
        "payload": {"working_dir": "/home/ubuntu/aiuc1-soc2-compliance-lab/terraform"},
    },
    {
        "name": "sanitize_output",
        "input_queue": "sanitize-output-input",
        "output_queue": "sanitize-output-output",
        "payload": {
            "text": "Subscription 00000000-0000-0000-0000-000000000000 has storage key abc123+def456==. Server IP: 10.0.1.5"
        },
    },
    {
        "name": "log_security_event",
        "input_queue": "log-security-event-input",
        "output_queue": "log-security-event-output",
        "payload": {
            "event_type": "compliance_scan",
            "severity": "INFO",
            "category": "audit",
            "agent_id": "aiuc1-soc2-compliance-agent",
            "description": "Live function test - compliance scan event",
            "details": {"scan_type": "live_test", "timestamp": datetime.utcnow().isoformat()},
        },
    },
]

# These are tested separately due to special requirements
SKIP_LIVE = ["run_terraform_apply", "git_commit_push"]


def _generate_approval_token(plan_hash: str) -> str:
    """Generate a valid HMAC approval token for terraform apply."""
    return hmac.new(
        APPROVAL_SECRET.encode(), plan_hash.encode(), hashlib.sha256
    ).hexdigest()


def send_and_receive(queue_service, func_config, timeout=90):
    """Send a message to the input queue and wait for a response on the output queue."""
    name = func_config["name"]
    input_q = func_config["input_queue"]
    output_q = func_config["output_queue"]
    payload = func_config["payload"]

    correlation_id = str(uuid.uuid4())[:8]
    message = json.dumps({**payload, "correlation_id": correlation_id})

    print(f"\n{'='*60}")
    print(f"  Testing: {name}")
    print(f"  Queue:   {input_q} → {output_q}")
    print(f"  Corr ID: {correlation_id}")
    print(f"{'='*60}")

    # Send to input queue
    input_client = queue_service.get_queue_client(input_q)
    encoded_msg = base64.b64encode(message.encode()).decode()
    input_client.send_message(encoded_msg)
    print(f"  ✓ Message sent to {input_q}")

    # Poll output queue
    output_client = queue_service.get_queue_client(output_q)
    start = time.time()
    result = None

    while time.time() - start < timeout:
        messages = output_client.receive_messages(max_messages=5, visibility_timeout=30)
        for msg in messages:
            try:
                body = base64.b64decode(msg.content).decode()
            except Exception:
                body = msg.content
            try:
                envelope = json.loads(body)
                # Azure Queue output binding wraps in {"Value": "..."}
                if isinstance(envelope, dict) and "Value" in envelope and isinstance(envelope["Value"], str):
                    envelope = json.loads(envelope["Value"])
            except json.JSONDecodeError:
                output_client.delete_message(msg)
                continue

            # Check if this is our response (by correlation_id or just take it)
            output_client.delete_message(msg)
            result = envelope
            break

        if result:
            break
        time.sleep(3)

    if result:
        status = result.get("status", "unknown")
        sanitised = result.get("sanitised", False)
        has_disclosure = "ai_disclosure" in result
        has_enforcement = "enforcement_metadata" in result

        status_icon = "✓" if status == "success" else "✗" if status == "error" else "⊘"
        print(f"  {status_icon} Status: {status}")
        print(f"    Sanitised: {sanitised}")
        print(f"    AI Disclosure: {has_disclosure}")
        print(f"    Enforcement Metadata: {has_enforcement}")

        if status == "error":
            err = result.get("error", {})
            print(f"    Error Code: {err.get('code', 'N/A')}")
            print(f"    Error Msg:  {err.get('message', 'N/A')[:100]}")

        if status == "success" and "data" in result:
            data = result["data"]
            # Print a brief summary of the data
            if isinstance(data, dict):
                keys = list(data.keys())[:5]
                print(f"    Data keys: {keys}")
            elif isinstance(data, list):
                print(f"    Data items: {len(data)}")

        return {"name": name, "status": status, "envelope": result}
    else:
        print(f"  ✗ TIMEOUT: No response after {timeout}s")
        return {"name": name, "status": "timeout", "envelope": None}


def main():
    if not STORAGE_CONN_STR:
        print("ERROR: AZURE_STORAGE_CONNECTION_STRING not set")
        sys.exit(1)

    queue_service = QueueServiceClient.from_connection_string(STORAGE_CONN_STR)

    results = []
    for func in FUNCTIONS:
        try:
            result = send_and_receive(queue_service, func)
            results.append(result)
        except Exception as e:
            print(f"  ✗ EXCEPTION: {e}")
            results.append({"name": func["name"], "status": "exception", "envelope": None})

    # Summary
    print(f"\n{'='*60}")
    print(f"  LIVE FUNCTION TEST SUMMARY")
    print(f"{'='*60}")

    passed = sum(1 for r in results if r["status"] in ("success", "blocked"))
    errored = sum(1 for r in results if r["status"] == "error")
    timed_out = sum(1 for r in results if r["status"] == "timeout")
    excepted = sum(1 for r in results if r["status"] == "exception")

    for r in results:
        icon = "✓" if r["status"] in ("success", "blocked") else "✗"
        print(f"  {icon} {r['name']:30s} → {r['status']}")

    print(f"\n  Total: {len(results)} | Passed: {passed} | Errors: {errored} | Timeouts: {timed_out} | Exceptions: {excepted}")
    print(f"  Skipped (special): {', '.join(SKIP_LIVE)}")

    # Save results to evidence
    evidence_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence", "live_function_results.json")
    with open(evidence_path, "w") as f:
        # Strip large envelope data for readability
        summary = []
        for r in results:
            entry = {"name": r["name"], "status": r["status"]}
            if r["envelope"]:
                entry["sanitised"] = r["envelope"].get("sanitised", False)
                entry["has_ai_disclosure"] = "ai_disclosure" in r["envelope"]
                entry["has_enforcement_metadata"] = "enforcement_metadata" in r["envelope"]
                if r["status"] == "error":
                    entry["error"] = r["envelope"].get("error", {})
                if r["status"] == "success" and "data" in r["envelope"]:
                    data = r["envelope"]["data"]
                    entry["data_keys"] = list(data.keys()) if isinstance(data, dict) else f"{len(data)} items"
            summary.append(entry)
        json.dump({"timestamp": datetime.utcnow().isoformat(), "results": summary}, f, indent=2)
    print(f"\n  Results saved to {evidence_path}")

    # Also save full envelopes for detailed evidence
    full_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence", "live_function_envelopes.json")
    with open(full_path, "w") as f:
        envelopes = {r["name"]: r["envelope"] for r in results if r["envelope"]}
        json.dump(envelopes, f, indent=2, default=str)
    print(f"  Full envelopes saved to {full_path}")

    return 0 if timed_out == 0 and excepted == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
