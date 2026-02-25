#!/usr/bin/env python3
"""
AIUC-1 SOC 2 Compliance Lab — Agent Tool Registration Script
=============================================================
Registers all 12 queue-based Azure Functions as AzureFunctionTool tools
on the Azure AI Foundry Agent Service.

Usage:
    export PROJECT_ENDPOINT="https://<your-project>.services.ai.azure.com/api"
    export MODEL_DEPLOYMENT_NAME="gpt-4o"
    python3 register_agent_tools.py

The script creates (or updates) a single agent with all 12 tools attached.
Storage endpoint is derived from the Function App's AzureWebJobsStorage.
"""

import os
import json
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient
from azure.ai.agents.models import AzureFunctionStorageQueue, AzureFunctionTool

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
STORAGE_SERVICE_ENDPOINT = os.environ.get(
    "STORAGE_SERVICE_ENDPOINT",
    "https://aiuc1funcstorage.queue.core.windows.net",
)
PROJECT_ENDPOINT = os.environ["PROJECT_ENDPOINT"]
MODEL_DEPLOYMENT_NAME = os.environ.get("MODEL_DEPLOYMENT_NAME", "gpt-4o")

# ---------------------------------------------------------------------------
# Tool Definitions — one AzureFunctionTool per function
# ---------------------------------------------------------------------------
TOOL_DEFINITIONS = [
    # ── Data Providers (6) ─────────────────────────────────────────────────
    {
        "name": "gap_analyzer",
        "description": (
            "Scan Azure resources for SOC 2 compliance gaps by CC category. "
            "Checks storage accounts (CC5), NSG rules (CC6), and SQL servers (CC7). "
            "Returns a list of gaps with severity, remediation guidance, and AIUC-1 control mappings."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cc_category": {
                    "type": "string",
                    "description": "SOC 2 Common Criteria category to scan (CC1-CC9).",
                },
            },
            "required": ["cc_category"],
        },
        "input_queue": "gap-analyzer-input",
        "output_queue": "gap-analyzer-output",
    },
    {
        "name": "scan_cc_criteria",
        "description": (
            "Scan Azure resources relevant to a SOC 2 CC category and return their "
            "current configuration state. Provides raw resource data for analysis."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cc_category": {
                    "type": "string",
                    "description": "SOC 2 Common Criteria category to scan (CC1-CC9).",
                },
            },
            "required": ["cc_category"],
        },
        "input_queue": "scan-cc-criteria-input",
        "output_queue": "scan-cc-criteria-output",
    },
    {
        "name": "evidence_validator",
        "description": (
            "Validate existence and metadata of compliance evidence artifacts. "
            "Checks Azure resources, policy states, documents, or log entries."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "evidence_type": {
                    "type": "string",
                    "description": "Type of evidence: azure_resource, policy_state, document, or log_entry.",
                },
                "target": {
                    "type": "string",
                    "description": "The target to validate (resource ID, policy name, document path, etc.).",
                },
                "cc_category": {
                    "type": "string",
                    "description": "Optional SOC 2 CC category for evidence mapping context.",
                },
            },
            "required": ["evidence_type", "target"],
        },
        "input_queue": "evidence-validator-input",
        "output_queue": "evidence-validator-output",
    },
    {
        "name": "query_access_controls",
        "description": (
            "Query Azure RBAC role assignments and NSG network access controls. "
            "Identifies overly permissive rules and high-privilege role assignments."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "description": "Optional resource group name to scope the query.",
                },
                "include_nsg": {
                    "type": "boolean",
                    "description": "Whether to include NSG rule analysis. Defaults to true.",
                },
            },
        },
        "input_queue": "query-access-controls-input",
        "output_queue": "query-access-controls-output",
    },
    {
        "name": "query_defender_score",
        "description": (
            "Query Microsoft Defender for Cloud secure score and security assessments. "
            "Returns the current score, max score, percentage, and unhealthy assessments."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "include_assessments": {
                    "type": "boolean",
                    "description": "Whether to include individual assessment details. Defaults to true.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of assessments to return (1-100). Defaults to 50.",
                },
            },
        },
        "input_queue": "query-defender-score-input",
        "output_queue": "query-defender-score-output",
    },
    {
        "name": "query_policy_compliance",
        "description": (
            "Query Azure Policy compliance states across subscriptions. "
            "Returns non-compliant policy states with resource details."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "include_details": {
                    "type": "boolean",
                    "description": "Whether to include detailed policy state information. Defaults to true.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (1-100). Defaults to 50.",
                },
            },
        },
        "input_queue": "query-policy-compliance-input",
        "output_queue": "query-policy-compliance-output",
    },
    # ── Action Functions (4) ───────────────────────────────────────────────
    {
        "name": "generate_poam_entry",
        "description": (
            "Generate a structured Plan of Action & Milestones (POA&M) entry for a "
            "compliance gap. Calculates remediation timelines based on severity."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cc_category": {
                    "type": "string",
                    "description": "SOC 2 CC category (CC1-CC9).",
                },
                "resource": {
                    "type": "string",
                    "description": "The Azure resource name or ID with the gap.",
                },
                "gap_description": {
                    "type": "string",
                    "description": "Description of the compliance gap.",
                },
                "severity": {
                    "type": "string",
                    "description": "Gap severity: critical, high, medium, or low.",
                },
                "responsible_party": {
                    "type": "string",
                    "description": "Person or team responsible for remediation.",
                },
            },
            "required": ["cc_category", "resource", "gap_description", "severity"],
        },
        "input_queue": "generate-poam-entry-input",
        "output_queue": "generate-poam-entry-output",
    },
    {
        "name": "run_terraform_plan",
        "description": (
            "Execute terraform plan with validation and approval gate. "
            "Checks for blocked resource types and generates an approval token "
            "if the plan passes validation. AIUC-1-11 requires human review."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "working_dir": {
                    "type": "string",
                    "description": "Terraform working directory path. Defaults to configured path.",
                },
                "target": {
                    "type": "string",
                    "description": "Optional terraform -target argument.",
                },
            },
        },
        "input_queue": "run-terraform-plan-input",
        "output_queue": "run-terraform-plan-output",
    },
    {
        "name": "run_terraform_apply",
        "description": (
            "Execute terraform apply with approval token validation. "
            "Requires a valid plan_hash and approval_token from run_terraform_plan. "
            "AIUC-1-11 enforces human-in-the-loop approval."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "plan_hash": {
                    "type": "string",
                    "description": "SHA-256 hash of the plan output from run_terraform_plan.",
                },
                "approval_token": {
                    "type": "string",
                    "description": "HMAC approval token from run_terraform_plan.",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent ID for audit logging.",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Terraform working directory path.",
                },
            },
            "required": ["plan_hash", "approval_token"],
        },
        "input_queue": "run-terraform-apply-input",
        "output_queue": "run-terraform-apply-output",
    },
    {
        "name": "git_commit_push",
        "description": (
            "Commit compliance artifacts to the Git repository. "
            "Includes pre-commit secret scanning and conventional commit message validation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of file paths to commit (relative to repo root).",
                },
                "message": {
                    "type": "string",
                    "description": "Conventional commit message (e.g. 'fix(cc5): disable public blob access').",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent ID for commit author attribution.",
                },
                "push": {
                    "type": "boolean",
                    "description": "Whether to push after commit. Defaults to true.",
                },
            },
            "required": ["files", "message"],
        },
        "input_queue": "git-commit-push-input",
        "output_queue": "git-commit-push-output",
    },
    # ── Safety Functions (2) ───────────────────────────────────────────────
    {
        "name": "sanitize_output",
        "description": (
            "Sanitise text or structured data by redacting sensitive values such as "
            "subscription IDs, access keys, connection strings, SAS tokens, and bearer tokens."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text string to sanitise. Provide either text or data, not both.",
                },
                "data": {
                    "type": "object",
                    "description": "JSON object to sanitise. Provide either text or data, not both.",
                },
            },
        },
        "input_queue": "sanitize-output-input",
        "output_queue": "sanitize-output-output",
    },
    {
        "name": "log_security_event",
        "description": (
            "Log a structured security event to Application Insights. "
            "Categories: scope_violation, secret_exposure, validation_failure, "
            "approval_denied, anomalous_behavior, compliance_finding, "
            "remediation_applied, access_event."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Event category (e.g. scope_violation, secret_exposure).",
                },
                "agent_id": {
                    "type": "string",
                    "description": "ID of the agent that triggered the event.",
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of the security event.",
                },
                "severity": {
                    "type": "string",
                    "description": "Optional severity override: DEBUG, INFO, WARNING, ERROR, CRITICAL.",
                },
                "cc_category": {
                    "type": "string",
                    "description": "Optional SOC 2 CC category related to the event.",
                },
                "details": {
                    "type": "object",
                    "description": "Optional additional structured details.",
                },
            },
            "required": ["category", "agent_id", "description"],
        },
        "input_queue": "log-security-event-input",
        "output_queue": "log-security-event-output",
    },
]


def build_azure_function_tools() -> list[AzureFunctionTool]:
    """Build AzureFunctionTool instances for all 12 functions."""
    tools = []
    for defn in TOOL_DEFINITIONS:
        tool = AzureFunctionTool(
            name=defn["name"],
            description=defn["description"],
            parameters=defn["parameters"],
            input_queue=AzureFunctionStorageQueue(
                queue_name=defn["input_queue"],
                storage_service_endpoint=STORAGE_SERVICE_ENDPOINT,
            ),
            output_queue=AzureFunctionStorageQueue(
                queue_name=defn["output_queue"],
                storage_service_endpoint=STORAGE_SERVICE_ENDPOINT,
            ),
        )
        tools.append(tool)
    return tools


def main():
    """Create or update the agent with all 12 tools."""
    credential = DefaultAzureCredential()
    project_client = AIProjectClient(
        endpoint=PROJECT_ENDPOINT,
        credential=credential,
    )

    # Build all tool definitions
    all_tools = build_azure_function_tools()

    # Combine all tool definitions into a single list
    combined_definitions = []
    for tool in all_tools:
        combined_definitions.extend(tool.definitions)

    # Create the agent
    agent = project_client.agents.create_agent(
        model=MODEL_DEPLOYMENT_NAME,
        name="aiuc1-soc2-compliance-agent",
        instructions=(
            "You are the AIUC-1 SOC 2 Compliance Agent. You help assess, monitor, and "
            "remediate SOC 2 Trust Services Criteria compliance gaps in Azure environments.\n\n"
            "You have 12 tools organized into three categories:\n"
            "- DATA PROVIDERS (6): gap_analyzer, scan_cc_criteria, evidence_validator, "
            "query_access_controls, query_defender_score, query_policy_compliance\n"
            "- ACTION FUNCTIONS (4): generate_poam_entry, run_terraform_plan, "
            "run_terraform_apply, git_commit_push\n"
            "- SAFETY FUNCTIONS (2): sanitize_output, log_security_event\n\n"
            "IMPORTANT RULES:\n"
            "1. Always sanitize outputs before presenting sensitive data (AIUC-1-17)\n"
            "2. Never run terraform apply without a valid approval token from terraform plan (AIUC-1-11)\n"
            "3. Log security events for any scope violations or anomalous behavior (AIUC-1-22)\n"
            "4. Use conventional commit messages when committing to git (AIUC-1-23)\n"
            "5. Stay within allowed resource groups — do not access out-of-scope resources (AIUC-1-09)\n"
        ),
        tools=combined_definitions,
    )

    print(f"Created agent: {agent.id}")
    print(f"  Name: {agent.name}")
    print(f"  Model: {agent.model}")
    print(f"  Tools: {len(combined_definitions)} tool definitions")

    # Print tool summary
    for tool in all_tools:
        print(f"  - {tool.name}: {tool.description[:60]}...")

    return agent


if __name__ == "__main__":
    main()
