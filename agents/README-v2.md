# AIUC-1 Agent Deployment (v2 — Function Calling)

This document provides everything you need to deploy the four AIUC-1 SOC 2 compliance agents to your Azure AI Foundry project using the modern `azure-ai-projects` SDK. This approach uses **Function Calling**, which provides a more direct, robust, and auditable trail for all tool activity, making it the recommended method for production and compliance-sensitive workloads.

## What's Included

1.  `deploy_agents_v2.py`: The new Python script that defines and deploys all four agents with their respective tools and system prompts using the `azure-ai-projects` SDK.
2.  `requirements-deploy.txt`: A list of Python packages required to run the new deployment script.
3.  `agent_config_v2.json`: A JSON file that will be generated after a successful deployment, containing the names and versions of the deployed agents.

## Prerequisites

Before you begin, ensure you have the following:

1.  **Python 3.9+** installed on your local machine.
2.  **Azure CLI** installed and authenticated (`az login`).
3.  **An Azure AI Foundry Project**: You must have an existing project in Azure AI Foundry. You will need the Project Endpoint URL.
4.  **Model Deployments**: You need deployments for `gpt-4.1-mini` and `gpt-4.1-nano` in your project.

## Step-by-Step Instructions

### Step 1: Set Up Your Environment

First, prepare your local environment by creating a virtual environment and installing the required packages.

```bash
# Navigate to the 'agents' directory in your project
cd /path/to/your/aiuc1-soc2-compliance-lab/agents

# Create a Python virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the required packages
pip install -r requirements-deploy.txt
```

### Step 2: Configure Environment Variables

The deployment script requires several environment variables. Create a file named `.env` in the `aiuc1-soc2-compliance-lab` root directory and add the following content. **Do not commit this file to source control.**

```dotenv
# .env

# The full Project Endpoint URL from your Azure AI Foundry project's overview page.
# It should look like: https://<your-hub-name>.services.ai.azure.com/api/projects/<your-project-name>
AZURE_AI_PROJECT_ENDPOINT="https://aiuc1-hub-eastus2.services.ai.azure.com/api/projects/aiuc1-soc2-lab"

# The names of your model deployments in the Foundry project.
AZURE_AI_MODEL_DEPLOYMENT_NAME_MINI="gpt-41-mini"
AZURE_AI_MODEL_DEPLOYMENT_NAME_NANO="gpt-41-nano"

# You also need your Azure Service Principal credentials for DefaultAzureCredential to work
AZURE_CLIENT_ID="your-service-principal-app-id"
AZURE_CLIENT_SECRET="your-service-principal-secret"
AZURE_TENANT_ID="your-azure-tenant-id"
AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
```

**How to find `AZURE_AI_PROJECT_ENDPOINT`:**
1.  Navigate to the [Azure Portal](https://portal.azure.com).
2.  Open your Azure AI Foundry Hub.
3.  Go to your Project.
4.  On the **Overview** page, you will find the **Project Endpoint** URL. Copy this entire URL.

### Step 3: Run the Deployment Script

With your environment set up and variables configured, you can now run the deployment script.

```bash
# Ensure you are in the 'agents' directory and your virtual environment is active
python3 deploy_agents_v2.py
```

The script will perform the following actions:
1.  Authenticate with Azure using your CLI credentials.
2.  Connect to your Azure AI Foundry project.
3.  Delete any existing agents with the same names to ensure a clean deployment.
4.  Create the four agents (`soc2-auditor`, `evidence-collector`, `policy-writer`, `iac-deployer`) with their tools and system prompts defined.
5.  Print a summary of the deployed agents.
6.  Save the configuration to `agent_config_v2.json`.

### Step 4: Verify in Foundry Studio

After the script completes successfully, navigate to your project in the **Azure AI Foundry Studio**.

1.  Go to the **Build** tab.
2.  You will see your four newly deployed agents listed.
3.  Click on an agent to open its playground. You can see its system prompt and the list of `FunctionTool` definitions in the **Tools** section.

These agents are now ready to be used. Because they use Function Calling, every tool execution will be fully traced in Application Insights, providing the robust audit trail required for your SOC 2 compliance demonstration.
