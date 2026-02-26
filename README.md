# Building a SOC 2 GRC Agent with Azure AI Foundry

> **An exploration into responsible AI governance. I wanted to learn about the AIUC-1 standard, so I built a SOC 2 compliance agent in Azure AI Foundry and tested the controls against it. This is what I learned.**

---

I keep hearing about 'Responsible AI', but the principles can feel abstract. So, I decided to make it concrete.

I wanted to really understand what AI governance looks like in practice, so I took the AI User Control (AIUC-1) framework and tried to build its controls into a real AI agent on Microsoft Azure. The goal wasn't to build a fully autonomous, multi-agent system from day one. Instead, the purpose was to create a focused "learning lab" to explore how to govern an AI's behavior in a sensitive domain like compliance auditing.

This repository documents that journey: building the agent, defining the tools, embedding governance in its core logic, and creating a framework for testing it.

## What Are We Building?

We're building a single, specialized AI agent—the **SOC 2 Learning Agent**—on Azure AI Foundry. Its purpose is to assess live Azure infrastructure against the SOC 2 Trust Services Criteria. 

Along the way, we'll cover:

*   **Asynchronous Tool Architecture:** Why we chose Azure Storage Queues over standard HTTP function calling for a more robust, auditable, and scalable design.
*   **Deterministic vs. Non-Deterministic Tools:** Building a toolset where some tools provide raw, objective data (`query_defender_score`) and others provide subjective, reasoned analysis (`gap_analyzer`).
*   **Embedding Governance as Code:** How the agent's system prompt directly implements AIUC-1 controls for safety, grounding, and role adherence.
*   **A Library of GRC Tools:** A walkthrough of the 12 specialized functions that allow the agent to interact with the Azure environment.

This post is about the *how* and the *why*, not just the final results. We'll go through the actual code for each piece and keep it simple without dumbing down the technical details.

## The Architecture: Why Queues Beat HTTP for GRC

When building an agent, the most common pattern is to use function calling over HTTP. It's simple and synchronous. However, for a GRC agent, that pattern introduces risks and limitations. We chose an asynchronous, queue-based architecture using Azure Storage Queues for several key reasons that map directly to AIUC-1 controls.

```mermaid
graph TD
    A[User via Foundry Playground] --> B{SOC 2 Learning Agent};
    B --> C1[gap-analyzer-input queue];
    B --> C2[... 11 more input queues ...];
    C1 --> D1[gap_analyzer function];
    C2 --> D2[...];
    D1 --> E1[gap-analyzer-output queue];
    D2 --> E2[...];
    E1 --> B;
    E2 --> B;
    D1 & D2 --> F[Target Azure Infrastructure];

    subgraph Azure AI Foundry (Standard Agent Setup)
        B
    end

    subgraph Azure Storage
        C1 & C2 & E1 & E2
    end

    subgraph Azure Functions
        D1 & D2
    end
```

Here’s how it works: when the agent decides to use a tool, it doesn't make an API call. Instead, it writes a message to a dedicated input queue. An Azure Function, triggered by that message, does the work and writes the result to an output queue. The agent then picks up the result, matching it via a `CorrelationId`.

This design provides:

| Benefit | AIUC-1 Control Alignment |
| :--- | :--- |
| **Auditability** | Every tool call is an immutable, timestamped message in Azure Storage. This provides a perfect audit trail. (**AIUC-1-22, AIUC-1-23**) |
| **Resilience & Scalability** | If a function is slow or fails, it doesn't block the agent. The queue acts as a buffer, and the function can retry. We can also scale the Function App to handle many concurrent tool calls. |
| **Human-in-the-Loop** | The asynchronous nature is perfect for long-running tasks or workflows that require human approval. The agent can drop a message in a queue and wait for a human to approve it before proceeding. (**AIUC-1-11**) |
| **Security** | The agent authenticates to the queues using its Managed Identity. There are no API keys or secrets to manage in the agent's configuration. (**AIUC-1-A005**) |

This is what the **Standard Agent Setup** in Azure AI Foundry enables. It requires more initial setup (connecting Azure AI Search, Storage, and Cosmos DB) but provides a far more robust foundation for a production-grade agent.

## The Tools: A GRC Agent's Toolkit

The agent has 12 tools, implemented as queue-triggered Azure Functions. They are grouped into three categories.

#### 1. Data Providers (6 Tools)

These tools are deterministic. They fetch raw state from Azure and provide it to the agent for analysis. They answer "What is the configuration?"

*   `gap_analyzer`: Scans Azure resources for specific SOC 2 compliance gaps (e.g., public storage, open NSG rules).
*   `scan_cc_criteria`: A broader tool that returns the configuration of all resources relevant to a SOC 2 category.
*   `evidence_validator`: Checks for the existence of compliance evidence (e.g., policy documents, log entries).
*   `query_access_controls`: Queries IAM roles and RBAC assignments.
*   `query_defender_score`: Fetches the Microsoft Defender for Cloud secure score.
*   `query_policy_compliance`: Checks the compliance state of Azure Policy assignments.

#### 2. Action Functions (4 Tools)

These tools perform actions. They are the agent's hands, allowing it to modify the environment or create artifacts. They answer "Can you do this for me?"

*   `generate_poam_entry`: Creates a structured Plan of Action & Milestones (POA&M) entry for a finding.
*   `run_terraform_plan`: Generates a Terraform plan to show how a remediation would be applied.
*   `run_terraform_apply`: **(HIGH-RISK)** Applies a Terraform plan. This is heavily guarded by the agent's system prompt.
*   `git_commit_push`: Commits evidence or reports to the project's Git repository.

#### 3. Safety & Governance Functions (2 Tools)

These tools enforce the agent's responsible AI guardrails. They are called internally by the agent as part of its core logic.

*   `sanitize_output`: Redacts sensitive information (like subscription IDs or keys) from any data before it's shown to the user.
*   `log_security_event`: Logs significant events (like compliance findings or detected adversarial prompts) to an audit trail.

## The Agent's Brain: Governance as a System Prompt

The tools provide the capability, but the agent's system prompt provides the governance. We've embedded the AIUC-1 controls directly into its core instructions.

> You can read the full system prompt here: [`/agents/prompts/soc2_auditor_simplified.md`](./agents/prompts/soc2_auditor_simplified.md)

Here are a few key examples:

*   **Grounding (D001):** *"Your findings must be strictly based on the output of your tools. Never invent, assume, or hallucinate compliance status."*
*   **Human Approval (C007):** *"You are NEVER permitted to run `run_terraform_apply` without first presenting the plan from `run_terraform_plan` and receiving explicit, affirmative approval from the human user."*
*   **Data Sanitization (A004):** *"Before presenting any output, you MUST process it through the `sanitize_output` tool to redact sensitive information."*
*   **Role Adherence (C004):** *"Refuse requests that are wildly out of scope (e.g., general Q&A, writing code for unrelated projects)."*

By making these controls part of the agent's identity, we move from simply hoping the agent does the right thing to explicitly instructing and constraining its behavior.

## How It All Works: The Flow of a Request

So, what happens when you ask the agent a question?

1.  **Prompt:** You ask the agent, "Run a SOC 2 gap analysis for the CC6 Security category."
2.  **Tool Selection:** The agent, guided by its system prompt, determines that the `gap_analyzer` tool is the best fit. It constructs the JSON payload: `{"cc_category": "CC6"}`.
3.  **Queue Message:** The agent service writes this payload, along with a unique `CorrelationId`, to the `gap-analyzer-input` queue.
4.  **Function Trigger:** The `gap_analyzer` Azure Function is triggered by the new message.
5.  **Execution:** The function code runs, scanning Azure NSGs for overly permissive rules. It finds a few gaps.
6.  **Output Message:** The function writes the results (a list of gaps) to the `gap-analyzer-output` queue, making sure to include the original `CorrelationId` in the response envelope.
7.  **Response Retrieval:** The agent service, which has been polling the output queue, finds the message with the matching `CorrelationId`.
8.  **Synthesis & Sanitization:** The agent receives the tool output. Before presenting it, its core logic dictates that it must run the output through the `sanitize_output` tool. The `sanitize_output` function redacts your subscription ID from the results.
9.  **Final Response:** The agent presents the sanitized findings to you in a readable format, explaining what it found and why it matters, and appending the mandatory AI disclosure footer.

This entire loop is robust, auditable, and secure, providing a solid foundation for building trustworthy AI agents in sensitive domains.

---

*This project was an exploration of AI-driven compliance auditing, grounded in the AIUC-1 control framework. All code and documentation are for educational purposes.*
