#!/usr/bin/env python3
"""
AIUC-1 SOC 2 Compliance Lab — Simplified Agent Deployment Script
==============================================================

Deploys a single AI agent to Azure AI Foundry for the learning-focused version of the project.

This script deploys the "SOC 2 Learning Agent," a single, powerful agent equipped with all 12 GRC tools from the function library. The goal is to create a focused environment for manually testing AIUC-1 controls and SOC 2 audit scenarios through the Foundry Studio UI.

Key Features:
  - Deploys one agent instead of four.
  - Uses `azure-ai-projects` SDK (v2.0.0b3+).
  - Defines tools using `FunctionTool` for direct, traceable function calling.
  - The agent is designed for interactive testing and learning.

Environment Variables Required (in a .env file):
  AZURE_AI_PROJECT_ENDPOINT   - The full project endpoint URL from the Foundry portal.
  AZURE_AI_MODEL_DEPLOYMENT_NAME_MINI - Deployment name for gpt-4.1-mini.
"""

import json
import os
import sys
from dotenv import load_dotenv

from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import PromptAgentDefinition, FunctionTool
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError

# --- Configuration ---
load_dotenv()

PROJECT_ENDPOINT = os.environ.get("AZURE_AI_PROJECT_ENDPOINT")
if not PROJECT_ENDPOINT:
    sys.exit("Error: AZURE_AI_PROJECT_ENDPOINT environment variable is not set.")

MODEL_MINI = os.environ.get("AZURE_AI_MODEL_DEPLOYMENT_NAME_MINI", "gpt-41-mini")

# --- Tool Definitions ---
def make_tool(name: str, description: str, parameters: dict) -> FunctionTool:
    return FunctionTool(name=name, description=description, parameters=parameters, strict=True)

# Define all 12 tools for the single agent
ALL_TOOLS = [
    make_tool(
        name="gap_analyzer",
        description="Analyze the Azure environment for SOC 2 compliance gaps across all CC criteria.",
        parameters={
            "type": "object",
            "properties": {
                "subscription_id": {"type": "string", "description": "Azure subscription ID to analyze."},
                "resource_group": {"type": "string", "description": "Optional resource group to scope the analysis."},
                "criteria": {"type": "array", "items": {"type": "string"}, "description": "Optional list of specific CC criteria to check."}
            },
            "required": ["subscription_id"]
        }
    ),
    make_tool(
        name="scan_cc_criteria",
        description="Scan Azure resources against a specific SOC 2 Common Criteria (CC) control.",
        parameters={
            "type": "object",
            "properties": {
                "criteria_id": {"type": "string", "description": "SOC 2 CC criteria identifier (e.g., 'CC6.1')."},
                "subscription_id": {"type": "string", "description": "Azure subscription ID to scan."},
                "resource_group": {"type": "string", "description": "Optional resource group to scope the scan."}
            },
            "required": ["criteria_id", "subscription_id"]
        }
    ),
    make_tool(
        name="evidence_validator",
        description="Validate that compliance evidence artifacts exist and are properly formatted.",
        parameters={
            "type": "object",
            "properties": {
                "criteria_id": {"type": "string", "description": "SOC 2 CC criteria identifier to validate evidence for."},
                "subscription_id": {"type": "string", "description": "Azure subscription ID for technical evidence validation."},
                "evidence_type": {"type": "string", "description": "Type of evidence to validate.", "enum": ["technical", "non_technical", "both"]}
            },
            "required": ["criteria_id", "subscription_id"]
        }
    ),
    make_tool(
        name="query_defender_score",
        description="Query Microsoft Defender for Cloud secure score and security recommendations.",
        parameters={
            "type": "object",
            "properties": {"subscription_id": {"type": "string", "description": "Azure subscription ID to query."}},
            "required": ["subscription_id"]
        }
    ),
    make_tool(
        name="query_policy_compliance",
        description="Query Azure Policy compliance state for the subscription.",
        parameters={
            "type": "object",
            "properties": {
                "subscription_id": {"type": "string", "description": "Azure subscription ID to query."},
                "resource_group": {"type": "string", "description": "Optional resource group to scope the query."}
            },
            "required": ["subscription_id"]
        }
    ),
    make_tool(
        name="query_access_controls",
        description="Query Azure RBAC role assignments and access control configurations.",
        parameters={
            "type": "object",
            "properties": {
                "subscription_id": {"type": "string", "description": "Azure subscription ID to query."},
                "resource_group": {"type": "string", "description": "Optional resource group to scope the query."},
                "include_classic": {"type": "boolean", "description": "Whether to include classic administrator assignments."}
            },
            "required": ["subscription_id"]
        }
    ),
    make_tool(
        name="git_commit_push",
        description="Commit evidence artifacts to the compliance repository and push to remote.",
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path of the evidence file to commit."},
                "commit_message": {"type": "string", "description": "Descriptive commit message."},
                "branch": {"type": "string", "description": "Git branch to commit to."}
            },
            "required": ["file_path", "commit_message"]
        }
    ),
    make_tool(
        name="run_terraform_plan",
        description="Run `terraform plan` for a remediation module and return the execution plan.",
        parameters={
            "type": "object",
            "properties": {
                "module_path": {"type": "string", "description": "Path to the Terraform module directory."},
                "variables": {"type": "object", "description": "Terraform variable key-value pairs."},
                "target_resource_group": {"type": "string", "description": "Target resource group for the remediation.", "enum": ["rg-production", "rg-development"]}
            },
            "required": ["module_path", "target_resource_group"]
        }
    ),
    make_tool(
        name="run_terraform_apply",
        description="Apply a previously planned Terraform remediation. REQUIRES human approval.",
        parameters={
            "type": "object",
            "properties": {
                "plan_id": {"type": "string", "description": "The plan ID returned by run_terraform_plan."},
                "approval_reference": {"type": "string", "description": "Human approval reference."}
            },
            "required": ["plan_id", "approval_reference"]
        }
    ),
    make_tool(
        name="generate_poam_entry",
        description="Generate a Plan of Action and Milestones (POA&M) entry for a finding.",
        parameters={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Unique identifier for the compliance finding."},
                "criteria_id": {"type": "string", "description": "SOC 2 CC criteria this finding relates to."},
                "description": {"type": "string", "description": "Description of the finding."},
                "remediation_plan": {"type": "string", "description": "Proposed remediation steps."},
                "target_date": {"type": "string", "description": "Target completion date in ISO 8601 format."},
                "responsible_party": {"type": "string", "description": "Person or team responsible."}
            },
            "required": ["finding_id", "criteria_id", "description", "remediation_plan", "target_date", "responsible_party"]
        }
    ),
    make_tool(
        name="sanitize_output",
        description="Sanitize text output by redacting secrets, PII, and sensitive identifiers. MUST be called before returning any tool results to the user.",
        parameters={
            "type": "object",
            "properties": {"text": {"type": "string", "description": "The raw text to sanitize."}},
            "required": ["text"]
        }
    ),
    make_tool(
        name="log_security_event",
        description="Log a security-relevant event to Application Insights for audit trail.",
        parameters={
            "type": "object",
            "properties": {
                "event_type": {"type": "string", "description": "Type of security event.", "enum": ["compliance_gap_found", "evidence_missing", "policy_violation", "unauthorized_access_attempt", "prompt_injection_attempt", "terraform_blocked", "high_risk_finding", "remediation_applied"]},
                "severity": {"type": "string", "description": "Severity level.", "enum": ["low", "medium", "high", "critical"]},
                "description": {"type": "string", "description": "Human-readable description of the event."},
                "metadata": {"type": "object", "description": "Additional structured metadata."}
            },
            "required": ["event_type", "severity", "description"]
        }
    )
]

# --- Agent Definition ---
def _load_prompt(filename: str) -> str:
    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", filename)
    with open(prompt_path, "r") as f:
        return f.read()

LEARNING_AGENT = {
    "name": "soc2-learning-agent",
    "display_name": "SOC 2 Learning Agent",
    "model": MODEL_MINI,
    "instructions": _load_prompt("soc2_auditor_simplified.md"),
    "tools": ALL_TOOLS,
    "metadata": {
        "project_version": "simplified",
        "aiuc1_controls": "All",
        "agent_type": "auditor_learner",
    },
}

# --- Deployment Main Logic ---
def main():
    """Main deployment function."""
    print("=" * 70)
    print("AIUC-1 SOC 2 Lab — Simplified Agent Deployment")
    print("=" * 70)
    print(f"Project Endpoint: {PROJECT_ENDPOINT}")
    print()

    try:
        print("[1/3] Authenticating and connecting to Azure AI Project...")
        credential = DefaultAzureCredential()
        project_client = AIProjectClient(endpoint=PROJECT_ENDPOINT, credential=credential)
        print("  ✓ Connected successfully.")

        print("\n[2/3] Checking for and deleting existing agent version...")
        try:
            existing_versions = project_client.agents.list_versions(name=LEARNING_AGENT["name"])
            for v in existing_versions:
                print(f"  Deleting existing agent: {v.name} (version: {v.version})")
                project_client.agents.delete_version(name=v.name, version=v.version)
        except ResourceNotFoundError:
            print(f"  No existing agent named '{LEARNING_AGENT['name']}' found. Skipping.")
        print("  ✓ Cleanup complete.")

        print("\n[3/3] Deploying the new SOC 2 Learning Agent...")
        agent_def = LEARNING_AGENT
        
        agent_definition = PromptAgentDefinition(
            model=agent_def["model"],
            instructions=agent_def["instructions"],
            tools=agent_def["tools"],
        )

        created_agent = project_client.agents.create_version(
            agent_name=agent_def["name"],
            definition=agent_definition,
            display_name=agent_def["display_name"],
            description=f"AIUC-1 SOC 2 Learning Agent — {agent_def['display_name']}",
            tags=agent_def["metadata"]
        )

        result = {
            "id": created_agent.id,
            "name": created_agent.name,
            "version": created_agent.version,
            "display_name": created_agent.display_name,
            "model": agent_def["model"],
            "tools_count": len(agent_def["tools"]),
            "tool_names": [t.name for t in agent_def["tools"]],
        }
        print(f"    ✓ Created: {created_agent.name} (version: {created_agent.version})")

        print("\n" + "=" * 70)
        print("Deployment Summary")
        print("=" * 70)
        print(f"  {result['display_name']:25s} | {result['name']:25s} | v{result['version']:<5} | {result['tools_count']} tools")
        print("\nDeployment complete. Agent is now available in the Foundry Studio.")
        print("=" * 70)

        config_path = os.path.join(os.path.dirname(__file__), "agent_config.json")
        with open(config_path, "w") as f:
            json.dump({"agent": result}, f, indent=2)
        print(f"\nAgent configuration saved to: {config_path}")

    except Exception as e:
        print(f"\n✗ Deployment failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
