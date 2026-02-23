# Walkthrough: Connecting Your GRC Tools to the Foundry Agent

This guide walks you through connecting your 12 GRC Azure Functions to the SOC 2 Learning Agent in Azure AI Foundry. This follows the methodology where the agent provides reasoning, and the functions act as simple, stateless data providers.

We will use the `register_tools.py` script to do this. The script uses the Azure AI SDK to tell your Foundry agent about your deployed functions, defining them as callable "tools."

---

### Step 1: Get Your Azure Function App Details

Before running the script, you need two pieces of information from the Azure Portal:

1.  **Function App URL**: The public URL of your deployed Function App.
2.  **Function App Master Key**: The `_master` host key that grants access to all functions.

**How to find them:**

1.  Navigate to your Function App in the Azure Portal.
2.  The URL is on the main **Overview** page.
3.  For the key, go to **App Keys** under the "Functions" section in the left menu.
4.  Copy the value of the `_master` key.

### Step 2: Set Up Your Environment

The `register_tools.py` script can get these values from a `.env` file or ask you for them directly. For simplicity, we'll let it ask you the first time.

You also need to be logged into Azure in your terminal:

```bash
# Log in to your Azure account
az login

# Set the subscription your Foundry project is in
az account set --subscription "Your-Subscription-Name-or-ID"
```

### Step 3: Run the Registration Script

This is the core step. The script handles everything for you.

1.  Open a terminal and navigate to the `agents` directory inside the project:
    ```bash
    cd /path/to/your/aiuc1-soc2-compliance-lab/agents
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements-deploy.txt
    ```

3.  Run the script:
    ```bash
    python register_tools.py
    ```

4.  The script will prompt you for your Function App URL and Master Key. Paste them in.

**What the script does:**

*   It constructs an `OpenAITool` definition for each of your 12 functions.
*   This definition tells the agent:
    *   The function's name (e.g., `grc_tools_gap_analyzer`).
    *   A description of what it does.
    *   The parameters it expects (e.g., `cc_category`, `resource_group`).
    *   The exact HTTP endpoint to call.
    *   The API key to use for authentication.
*   It then connects to your Foundry project and creates a new version of the `soc2-learning-agent`, attaching the system prompt and all 12 tool definitions.

If successful, you will see a confirmation message: `✅ Successfully registered the agent and its tools!`

### Step 4: Test in the Foundry Playground

Now for the fun part. Your agent is now aware of its tools. You can test its ability to reason and use them.

1.  Go to your project in the **Azure AI Studio** (Foundry Portal).
2.  Navigate to **Agents** and open the **Playground** for the `soc2-learning-agent`.
3.  Under the **Tools** section, you should now see all 12 of your GRC functions listed.

**Example Prompts to Try:**

*   **Test Tool Selection:**
    > `Is my storage account compliant with CC5?`

    The agent should reason that this requires scanning for gaps and decide to call the `grc_tools_gap_analyzer` function. It will then ask you for the `resource_group` parameter.

*   **Test Parameter Elicitation:**
    > `Run a gap analysis.`

    The agent knows `gap_analyzer` needs a `cc_category` and `resource_group`. It should ask you for this missing information before it can proceed.

*   **Test Human-in-the-Loop (Approval):**
    > `I have a finding that needs a remediation plan. The module is called 'fix-storage-tls'. Run the terraform apply.`

    The agent should refuse. It will see that the `run_terraform_apply` tool requires a `human_approval_confirmation` parameter. It should state that it has prepared the plan but needs your explicit approval to apply it.

This setup perfectly aligns with Ethan Troy's methodology: the agent is the reasoning engine that decides *which* tool to use and *why*, while the Azure Functions are the simple, deterministic endpoints that just provide the data.
