# Foundry Agent Setup Guide (OpenAPI + UI-Driven)

This guide provides the **simplest, most UI-driven path** to connect your 12 Azure Functions as tools to your Foundry agent. This allows you to properly validate the AIUC-1 controls end-to-end.

**The core problem:** The Foundry portal UI does *not* let you define custom tools from scratch. You can only attach tools that are already defined, either through built-in options (like Bing Search) or by referencing a pre-existing definition (like an OpenAPI spec).

**The solution:** We will use the **OpenAPI tool** option. This is the most UI-friendly approach because it lets you do most of the work in the portal.

---

## The 3-Step Process

1.  **Create the OpenAPI Specification** (I have already done this for you).
2.  **Create a "Connection" in the Foundry Portal** (This is a one-time, click-through UI setup to securely store your Function App's API key).
3.  **Add the OpenAPI Tool in the Agent Builder UI** (This is where you point the agent to your spec file and the connection you just created).

---

### Step 1: The OpenAPI Specification (Already Done)

I have already generated a complete OpenAPI 3.0 specification for all 12 of your Azure Functions. It's located in the repo at `functions_openapi.json`.

This file tells Foundry what your tools are, what parameters they take, and how to call them.

### Step 2: Create the API Key Connection in the Portal (5 Clicks)

This is how you securely give your agent the API key for your Function App without hardcoding it.

1.  Go to the **Azure AI Studio** and open your project.
2.  On the left navigation, click the **Settings** gear icon (⚙️).
3.  Under **Connected resources**, click **+ New connection**.
4.  In the "Create a new connection" panel:
    *   **Connection type**: Select **Custom**.
    *   **Connection name**: `aiuc1-soc2-functions-key`
    *   **Add key-value pairs**:
        *   **Key**: `x-functions-key`
        *   **Value**: `YOUR_FUNCTION_APP_MASTER_KEY` (Paste your Function App's `_master` key here)
5.  Click **Create**.


### Step 3: Add the OpenAPI Tool to Your Agent (in the UI)

Now, you'll tell your agent to use the spec file and the connection you just made.

1.  In your AI Studio project, go to the **Build** tab.
2.  Click on your **SOC 2 Learning Agent** to open the agent builder.
3.  Click on the **Tools** section to expand it.
4.  Click **+ Add a tool**.
5.  From the dropdown, select **OpenAPI tool**.
6.  In the "Add a tool" panel:
    *   **OpenAPI spec**: Upload the `functions_openapi.json` file from your local clone of the repository.
    *   **Authentication**: Select **API Key**.
    *   **Connection**: From the dropdown, select the `aiuc1-soc2-functions-key` connection you created in Step 2.
7.  Click **Add**.

---

## You're Done.

That's it. Your agent now has all 12 functions available as callable tools. You can go to the **Playground** and start testing the AIUC-1 controls by giving it prompts like:

*   `"Scan the 'aiuc1-lab-prod' resource group for CC5 compliance gaps."`
*   `"What are the access controls for the main storage account?"`
*   `"There is a finding that a storage account allows public access. Generate a POA&M entry for it."`

You will see the agent call the appropriate function (`gap_analyzer`, `query_access_controls`, `generate_poam_entry`) in the debug console, and you can validate that the controls in your system prompt are being enforced.
