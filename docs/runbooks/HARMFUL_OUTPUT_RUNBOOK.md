_This document is generated and maintained by the Policy Writer agent._

# AI Failure Runbook: Harmful or Biased Output

**Control**: AIUC-1 E002

**Purpose**: This runbook provides the immediate steps to take in response to an AI agent generating harmful, biased, or otherwise inappropriate content.

## 1. Triage & Identification

**Objective**: Confirm the harmful output and identify the source.

| Step | Action | Owner | Evidence |
| :--- | :--- | :--- | :--- |
| 1.1 | **Receive Alert**: Receive an alert from Azure AI Content Safety, a user report (via the dashboard's "Flag as Incorrect" button), or manual observation. | Pete | Alert Screenshot / User Report |
| 1.2 | **Review Output**: Examine the flagged output in the agent's logs (Application Insights) or the compliance dashboard to confirm its harmful nature. | Pete | App Insights Log Entry |
| 1.3 | **Identify Agent & Prompt**: Identify which agent produced the output and the specific input prompt or data that triggered it. | Pete | App Insights Query Results |

## 2. Containment

**Objective**: Prevent further generation of harmful content.

| Step | Action | Owner | Evidence |
| :--- | :--- | :--- | :--- |
| 2.1 | **Isolate Trigger**: If a specific prompt or data source is the cause, temporarily block it from being processed by the agent. | Pete | Code Change / Data Filter |
| 2.2 | **Update Content Safety Filters**: Adjust the severity thresholds or add custom blocklists in Azure AI Content Safety to automatically filter similar content in the future. | Pete | Content Safety Configuration JSON |
| 2.3 | **Take Output Offline**: If the harmful content is visible on the public-facing dashboard, immediately remove it. | Pete | Dashboard Screenshot (Before & After) |

## 3. Eradication

**Objective**: Address the root cause of the harmful output.

| Step | Action | Owner | Evidence |
| :--- | :--- | :--- | :--- |
| 3.1 | **Refine Agent Instructions**: Modify the agent's system prompt or instructions to explicitly forbid the generation of the identified harmful content category. | Pete | Git Commit SHA for Instruction Change |
| 3.2 | **Add Safety Test Case**: Create a new test case in the `tests/safety/` directory that specifically attempts to reproduce the harmful output. The test should fail until the fix is implemented correctly. | Pete | Git Commit SHA for New Test |

## 4. Recovery & Post-Mortem

**Objective**: Restore normal operations and ensure the issue does not recur.

| Step | Action | Owner | Evidence |
| :--- | :--- | :--- | :--- |
| 4.1 | **Run Test Suite**: Execute the full safety test suite to confirm that the fix is effective and has not introduced regressions. | CI/CD Pipeline | GitHub Actions Log |
| 4.2 | **Conduct Post-Mortem**: Document the incident, root cause, and remediation steps in a post-mortem report. | Pete | `docs/reports/post-mortems/YYYY-MM-DD-harmful-output-incident.md` |
| 4.3 | **Update Policy**: If necessary, update the `ACCEPTABLE_USE_POLICY.md` to reflect new restrictions. | Policy Writer (Approved by Pete) | Git Commit SHA |
