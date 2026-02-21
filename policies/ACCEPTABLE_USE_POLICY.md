_This document is generated and maintained by the Policy Writer agent._

# AI Agent Acceptable Use Policy

In accordance with AIUC-1 control E010, this policy defines the permitted and prohibited actions for each of the four autonomous GRC agents operating within the AIUC-1 SOC 2 Azure Foundry Compliance Lab.

## General Principles

1.  **Purpose Limitation**: Agents must only perform actions directly related to their defined roles in assessing Azure infrastructure against SOC 2 criteria.
2.  **Least Privilege**: Agents must operate with the minimum level of access required to fulfill their duties.
3.  **Human Oversight**: Critical actions, particularly those involving infrastructure changes, require explicit human approval.
4.  **No Third-Party Access**: No third-party users or systems are granted access to the agents or the underlying Azure environment, as per AIUC-1 control E009.

## Per-Agent Permitted & Prohibited Actions

| Agent | Permitted Actions | Prohibited Actions |
| :--- | :--- | :--- |
| **SOC 2 Auditor** | - Read SOC 2 criteria and AIUC-1 controls.<br>- Read evidence collected by the Evidence Collector.<br>- Analyze evidence against controls.<br>- Generate compliance findings and reports.<br>- Read its own instructions and historical outputs. | - Modify or delete any Azure resources.<br>- Access data outside the defined system boundary.<br>- Interact directly with the Evidence Collector or other agents.<br>- Write or commit code. |
| **Evidence Collector** | - Read agent instructions and target resource lists.<br>- Invoke Azure Functions to get Azure resource configurations.<br>- Read data from Azure Monitor and Microsoft Defender for Cloud.<br>- Save collected evidence to the designated storage location.<br>- Log all data collection activities to Application Insights. | - Modify or delete any Azure resources.<br>- Interpret compliance or make judgments on evidence.<br>- Access any data not explicitly listed in its target list.<br>- Store data in any location other than the official project repository. |
| **Policy Writer** | - Read AIUC-1 control requirements.<br>- Generate and update governance documents (e.g., AUP, Risk Taxonomy).<br>- Commit generated documents to the designated git repository folder.<br>- Read existing policy documents for context. | - Modify or delete any Azure resources.<br>- Generate code or infrastructure-as-code.<br>- Access any data unrelated to governance documentation.<br>- Approve its own generated content. |
| **IaC Deployer** | - Read Terraform code from the project repository.<br>- Execute `terraform plan` to preview infrastructure changes.<br>- Submit `terraform plan` output for mandatory human review.<br>- Upon approval, execute `terraform apply` to deploy resources.<br>- Read its own instructions and deployment history. | - **Apply any Terraform plan without explicit human approval.**<br>- Modify any resources outside the scope of the Terraform state.<br>- Create, modify, or delete any user accounts or permissions.<br>- Access application-level data or customer data. |
