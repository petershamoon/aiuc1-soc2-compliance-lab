# ---------------------------------------------------------------------------
# Register GRC Tools with Azure AI Foundry Agent
# ---------------------------------------------------------------------------
# This script connects to your Azure AI Foundry project and registers the 12
# GRC Azure Functions as callable tools for your SOC 2 Learning Agent.
#
# How it works:
# 1. Defines each of the 12 functions as an OpenAPI tool, specifying its
#    name, description, parameters, and the HTTP endpoint.
# 2. Connects to your Foundry project using your environment variables.
# 3. Creates a new version of the agent, attaching the system prompt and
#    all 12 tool definitions.
#
# Pre-requisites:
# 1. You have deployed the Azure Functions from the `/functions` directory.
# 2. You have the Function App URL and the master/host key.
# 3. You have set up your .env file with your Foundry project details.
#
# Running the script:
#    pip install -r requirements-deploy.txt
#    python register_tools.py
# ---------------------------------------------------------------------------

import os
import json
from dotenv import load_dotenv
from azure.ai.resources.client import AIClient
from azure.ai.resources.entities import(
    Tool, 
    OpenAITool, 
    PromptAgent,
    APIKeyConfiguration
)
from azure.identity import DefaultAzureCredential

# --- Configuration ---
load_dotenv("../.env")

AGENT_NAME = "soc2-learning-agent"
AGENT_DESCRIPTION = "A SOC 2 compliance auditing agent that uses tools to analyze Azure configurations against Trust Services Criteria."

# --- Load System Prompt ---
try:
    with open("prompts/soc2_auditor_simplified.md", "r") as f:
        SYSTEM_PROMPT = f.read()
except FileNotFoundError:
    print("ERROR: System prompt file not found. Make sure you are running this script from the `agents` directory.")
    exit(1)

# --- Get Function App Details from User ---
FUNCTION_APP_URL = os.getenv("AZURE_FUNCTION_APP_URL")
FUNCTION_APP_KEY = os.getenv("AZURE_FUNCTION_APP_KEY")

if not FUNCTION_APP_URL or not FUNCTION_APP_KEY:
    print("--- Azure Function App Details ---")
    print("I need the URL and master key for your deployed Azure Function App.")
    FUNCTION_APP_URL = input("Enter your Function App URL (e.g., https://my-soc2-funcs.azurewebsites.net): ").strip()
    FUNCTION_APP_KEY = input("Enter your Function App master/host key: ").strip()
    print("------------------------------------\n")

# --- Define the 12 GRC Tools ---

def create_grc_tool(name: str, description: str, parameters: dict, required_params: list) -> OpenAITool:
    """Factory function to create an OpenAITool definition for a GRC function."""
    return OpenAITool(
        name=f"grc_tools_{name}",
        description=description,
        type="openapi",
        parameters=[
            {
                "name": name,
                "type": "object",
                "properties": parameters,
                "required": required_params
            }
        ],
        url=f"{FUNCTION_APP_URL}/api/{name}",
        authentication=APIKeyConfiguration(
            key="code",
            value=FUNCTION_APP_KEY
        )
    )

# 1. Data Providers
gap_analyzer = create_grc_tool(
    name="gap_analyzer",
    description="Analyzes compliance gaps for a specific SOC 2 CC category (CC5, CC6, CC7) in a given resource group.",
    parameters={
        "cc_category": {"type": "string", "description": "The SOC 2 Common Criteria category to analyze (e.g., CC5.1, CC6.3)."},
        "resource_group": {"type": "string", "description": "The target Azure resource group to scan."}
    },
    required_params=["cc_category", "resource_group"]
)

scan_cc_criteria = create_grc_tool(
    name="scan_cc_criteria",
    description="Scans all resources of a specific type (e.g., Microsoft.Storage/storageAccounts) within a resource group.",
    parameters={
        "cc_category": {"type": "string", "description": "The SOC 2 CC category that maps to the resource type."},
        "resource_group": {"type": "string", "description": "The target Azure resource group."}
    },
    required_params=["cc_category", "resource_group"]
)

evidence_validator = create_grc_tool(
    name="evidence_validator",
    description="Validates if a specific Azure resource configuration meets a SOC 2 requirement.",
    parameters={
        "resource_id": {"type": "string", "description": "The full Azure Resource ID of the resource to validate."},
        "expected_config": {"type": "object", "description": "A dictionary of expected configuration key-value pairs."}
    },
    required_params=["resource_id", "expected_config"]
)

query_access_controls = create_grc_tool(
    name="query_access_controls",
    description="Queries the IAM role assignments for a specific Azure resource.",
    parameters={
        "resource_id": {"type": "string", "description": "The full Azure Resource ID."}
    },
    required_params=["resource_id"]
)

query_defender_score = create_grc_tool(
    name="query_defender_score",
    description="Retrieves the Microsoft Defender for Cloud secure score for the subscription.",
    parameters={},
    required_params=[]
)

query_policy_compliance = create_grc_tool(
    name="query_policy_compliance",
    description="Gets the Azure Policy compliance state for a specific resource group.",
    parameters={
        "resource_group": {"type": "string", "description": "The target Azure resource group."}
    },
    required_params=["resource_group"]
)

# 2. Action Functions
generate_poam_entry = create_grc_tool(
    name="generate_poam_entry",
    description="Generates a structured Plan of Action & Milestones (POA&M) entry for a compliance finding.",
    parameters={
        "weakness_description": {"type": "string", "description": "Detailed description of the compliance gap."},
        "affected_resource": {"type": "string", "description": "The name or ID of the affected resource."},
        "recommendation": {"type": "string", "description": "The recommended remediation action."}
    },
    required_params=["weakness_description", "affected_resource", "recommendation"]
)

run_terraform_plan = create_grc_tool(
    name="run_terraform_plan",
    description="Runs a 'terraform plan' for a given remediation module to show the proposed changes.",
    parameters={
        "module_name": {"type": "string", "description": "The name of the Terraform remediation module to run."}
    },
    required_params=["module_name"]
)

run_terraform_apply = create_grc_tool(
    name="run_terraform_apply",
    description="Runs a 'terraform apply' to execute a remediation plan. Requires human approval.",
    parameters={
        "module_name": {"type": "string", "description": "The name of the Terraform remediation module to apply."},
        "human_approval_confirmation": {"type": "string", "description": "A confirmation string indicating human approval was given."}
    },
    required_params=["module_name", "human_approval_confirmation"]
)

git_commit_push = create_grc_tool(
    name="git_commit_push",
    description="Commits and pushes changes (like a new POA&M) to the Git repository.",
    parameters={
        "commit_message": {"type": "string", "description": "The git commit message."},
        "file_path": {"type": "string", "description": "The path to the file to be committed."}
    },
    required_params=["commit_message", "file_path"]
)

# 3. Safety Functions
sanitize_output = create_grc_tool(
    name="sanitize_output",
    description="Scrubs sensitive information (like subscription IDs, keys, secrets) from text before displaying it.",
    parameters={
        "text_to_sanitize": {"type": "string", "description": "The text content to be sanitized."}
    },
    required_params=["text_to_sanitize"]
)

log_security_event = create_grc_tool(
    name="log_security_event",
    description="Logs a security-relevant event to the central logging system (Application Insights).",
    parameters={
        "event_name": {"type": "string", "description": "The name of the event (e.g., 'HighRiskFinding', 'HumanApprovalGiven')."},
        "event_details": {"type": "object", "description": "A dictionary of details about the event."}
    },
    required_params=["event_name", "event_details"]
)


ALL_TOOLS = [
    gap_analyzer, scan_cc_criteria, evidence_validator, query_access_controls,
    query_defender_score, query_policy_compliance, generate_poam_entry,
    run_terraform_plan, run_terraform_apply, git_commit_push, sanitize_output,
    log_security_event
]

# --- Connect to Azure AI and Register Agent ---
def main():
    """Main function to connect to Azure and register the agent with tools."""
    print("Connecting to Azure AI Foundry...")
    try:
        credential = DefaultAzureCredential()
        ai_client = AIClient.from_config(credential=credential)
    except Exception as e:
        print(f"ERROR: Could not connect to Azure AI Foundry. Check your .env file and `az login` status.")
        print(f"--> {e}")
        return

    print(f"Successfully connected to project: {ai_client.project_name}")

    print(f"\nCreating/updating agent '{AGENT_NAME}' with {len(ALL_TOOLS)} tools...")

    try:
        # Create the agent definition
        agent_definition = PromptAgent(
            name=AGENT_NAME,
            description=AGENT_DESCRIPTION,
            instructions=SYSTEM_PROMPT,
            tools=ALL_TOOLS,
            # This tells Foundry to use the agent's instructions to decide which tool to use
            tool_choice="auto" 
        )

        # Create or update the agent in the Foundry project
        agent_resource = ai_client.agents.create_or_update(agent_definition)

        print("\n✅ Successfully registered the agent and its tools!")
        print(f"   - Agent Name: {agent_resource.name}")
        print(f"   - Agent Version: {agent_resource.version}")
        print("\nYou can now go to the Azure AI Foundry portal, open the playground for this agent, and start testing.")

    except Exception as e:
        print(f"\n❌ ERROR: Failed to register the agent.")
        print(f"--> {e}")

if __name__ == "__main__":
    main()
