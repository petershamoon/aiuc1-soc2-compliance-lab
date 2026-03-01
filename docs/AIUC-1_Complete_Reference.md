# AIUC-1: Complete Standard Reference

## What Is AIUC-1?

AIUC-1 is the world's first dedicated standard and certifiable framework for AI agents, created by the Artificial Intelligence Underwriting Company (AIUC). It is designed to unlock enterprise adoption of agentic AI by giving security, risk, and procurement teams a concrete, auditable way to evaluate AI systems that act autonomously—calling tools, executing workflows, and interfacing with business operations.

Think of it as **SOC 2 for AI agents**: a familiar, actionable standard that combines independent auditing, technical testing, and ongoing assurance. Unlike many AI governance frameworks that remain theoretical, AIUC-1 translates high-level principles into specific, testable controls and technical evaluations.

**Key characteristics:**

- Covers six enterprise risk domains: Data & Privacy, Security, Safety, Reliability, Accountability, and Society
- Requires 50+ technical, operational, and legal safeguards
- Mandates quarterly third-party technical testing (adversarial red-teaming, jailbreak attempts, hallucination testing, etc.)
- Annual recertification with full audit
- Updated on a predictable quarterly cadence (Jan 15, Apr 15, Jul 15, Oct 15)
- Scoped per AI product/agent, not the entire organization

---

## Consortium & Technical Contributors

AIUC-1 was built with input from 500+ enterprise risk leaders and is maintained through three input channels:

**Technical Contributors (build the standard):** Cisco, MITRE, Stanford University, MIT, Orrick, Schellman, Cloud Security Alliance, CoreWeave, ElevenLabs, Google Cloud, UiPath, Intercom, Anthropic, Gray Swan, Scale AI, and more.

**Consortium Members (enterprise buyers shaping demand):** JPMorgan Chase, Microsoft, Fidelity Investments, Salesforce, Databricks, Visa, MongoDB, Brex, Supabase, Comcast, Cloudflare, BP, Meta, Kraken, and many others.

**Notable individuals:** Phil Venables (fmr. CISO Google Cloud), Jen Easterly (fmr. Director CISA), Jason Clinton (Deputy CISO Anthropic), Jim Reavis (CEO Cloud Security Alliance), Sanmi Koyejo (Stanford Trustworthy AI Research), Hyrum Anderson (Cisco), Christina Liaghati (MITRE ATLAS lead).

---

## The Six Domains: Complete Requirements

### DOMAIN A — DATA & PRIVACY
*Protect against data leakage, IP leakage, and training on user data without consent*

| ID | Requirement | Status | Capabilities |
|----|------------|--------|-------------|
| **A001** | **Establish input data policy** — Establish and communicate AI input data policies covering how customer data is used for model training, inference processing, data retention periods, and customer data rights | Mandatory | Universal |
| **A002** | **Establish output data policy** — Establish AI output ownership, usage, opt-out, and deletion policies to customers and communicate these policies | Mandatory | Universal |
| **A003** | **Limit AI agent data collection** — Implement safeguards to limit AI agent data access to task-relevant information based on user roles and context | Mandatory | Universal |
| **A004** | **Protect IP & trade secrets** — Implement safeguards or technical controls to prevent AI systems from leaking company intellectual property or confidential information | Mandatory | Universal |
| **A005** | **Prevent cross-customer data exposure** — Implement safeguards to prevent cross-customer data exposure when combining customer data from multiple sources | Mandatory | Universal |
| **A006** | **Prevent PII leakage** — Establish safeguards to prevent personal data leakage through AI outputs and logs | Mandatory | Universal |
| **A007** | **Prevent IP violations** — Implement safeguards and technical controls to prevent AI outputs from violating copyrights, trademarks, or other third-party intellectual property rights | Mandatory | External-facing |

**A002 Control Detail (representative example):**
- Define output ownership rights with clear distinctions between customer inputs and AI outputs
- Disclose consent and opt-out procedures for outputs
- Establish output usage policies communicated through accessible terms of service
- Document deletion procedures for AI-generated content

---

### DOMAIN B — SECURITY
*Protect against adversarial attacks like jailbreaks and prompt injections as well as unauthorized tool calls*

| ID | Requirement | Status | Capabilities |
|----|------------|--------|-------------|
| **B001** | **Third-party testing of adversarial robustness** — Implement adversarial testing program to validate system resilience against adversarial inputs and prompt injection attempts in line with adversarial threat taxonomy | Mandatory | Universal |
| **B002** | **Detect adversarial input** — Implement monitoring capabilities to detect and respond to adversarial inputs and prompt injection attempts | Optional | Universal |
| **B003** | **Manage public release of technical details** — Implement controls to prevent over-disclosure of technical information about AI systems and organizational details that could enable adversarial targeting | Optional | Universal |
| **B004** | **Prevent AI endpoint scraping** — Implement safeguards to prevent probing or scraping of external AI endpoints | Mandatory | Universal |
| **B005** | **Implement real-time input filtering** — Implement real-time input filtering using automated moderation tools | Optional | Text-gen, Voice-gen, Image-gen |
| **B006** | **Prevent unauthorized AI agent actions** — Implement safeguards to prevent AI agents from performing actions beyond intended scope and authorized privileges | Mandatory | Automation |
| **B007** | **Enforce user access privileges to AI systems** — Establish and maintain user access controls and admin privileges for AI systems in line with policy | Mandatory | Universal |
| **B008** | **Protect model deployment environment** — Implement security measures for AI model deployment environments including encryption, access controls and authorization | Mandatory | Universal |
| **B009** | **Limit output over-exposure** — Implement output limitations and obfuscation techniques to safeguard against information leakage | Mandatory | Text-gen, Voice-gen |

**B001 Control Detail (adversarial robustness):**
- Establish a taxonomy for adversarial risks (drawing on NIST AI 100-2e2023 attack classifications)
- Conduct comprehensive adversarial testing at least quarterly: structured red-teaming, prompt injection assessments, jailbreaking attempts, adversarial perturbation testing, semantic manipulation
- Maintain secure testing documentation with restricted access controls
- Establish improvement processes: assign owners, remediation timelines based on severity, track fixes through risk registers
- Align adversarial testing with broader security testing programs (integrate with penetration testing, share threat models across red/blue teams)
- **Evidence required:** Third-party evaluation report showing adversarial robustness testing — must include risk taxonomy tested, methodology, findings, secure documentation practices, improvement tracking with remediation timelines

---

### DOMAIN C — SAFETY
*Prevent harmful AI outputs and brand risk through testing, monitoring and safeguards*

| ID | Requirement | Status | Capabilities |
|----|------------|--------|-------------|
| **C001** | **Define AI risk taxonomy** — Establish a risk taxonomy that categorizes risks within harmful, out-of-scope, and hallucinated outputs, tool calls, and other risks based on application-specific usage | Mandatory | — |
| **C002** | **Conduct pre-deployment testing** — Conduct internal testing of AI systems prior to deployment across risk categories for system changes requiring formal review or approval | Mandatory | — |
| **C003** | **Prevent harmful outputs** — Implement safeguards or technical controls to prevent harmful outputs including distressed outputs, angry responses, high-risk advice, offensive content, bias, and deception | Mandatory | — |
| **C004** | **Prevent out-of-scope outputs** — Implement safeguards or technical controls to prevent out-of-scope outputs (e.g. political discussion, healthcare advice) | Mandatory | — |
| **C005** | **Prevent customer-defined high risk outputs** — Implement safeguards or technical controls to prevent additional high risk outputs as defined in risk taxonomy | Mandatory | — |
| **C006** | **Prevent output vulnerabilities** — Implement safeguards to prevent security vulnerabilities in outputs from impacting users | Mandatory | — |
| **C007** | **Flag high risk outputs** — Implement an alerting system that flags high-risk outputs for human review | Optional | — |
| **C008** | **Monitor AI risk categories** — Implement monitoring of AI systems across risk categories | Optional | — |
| **C009** | **Enable real-time feedback and intervention** — Implement mechanisms to enable real-time user feedback collection and intervention mechanisms | Optional | — |
| **C010** | **Third-party testing for harmful outputs** — Appoint expert third parties to evaluate system robustness to harmful outputs at least every 3 months | Mandatory | — |
| **C011** | **Third-party testing for out-of-scope outputs** — Appoint expert third parties to evaluate system robustness to out-of-scope outputs at least every 3 months | Mandatory | — |
| **C012** | **Third-party testing for customer-defined risk** — Appoint expert third-parties to evaluate system robustness to additional high-risk outputs as defined in risk taxonomy at least every 3 months | Mandatory | — |

**C006 Control Detail (output vulnerabilities):**
- Establish output sanitization and validation procedures: strip/encode HTML, JavaScript, shell syntax, iframe content; block unsafe URLs; validate structured output schemas
- Implement safety-specific labeling and handling protocols: mark untrusted data, distinguish third-party data, apply security controls based on content source and risk level
- Maintain detection and monitoring capabilities: log sanitization activities, alert on suspicious content patterns
- Detect advanced output-based attack patterns: prompt injection chains, model-output subversion (jailbreak tokens), payloads targeting downstream applications (command-line instructions, SQL queries), obfuscated exploits

---

### DOMAIN D — RELIABILITY
*Prevent hallucinations and unreliable tool calls to business systems*

| ID | Requirement | Status | Capabilities |
|----|------------|--------|-------------|
| **D001** | **Prevent hallucinated outputs** — Implement safeguards or technical controls to prevent hallucinated outputs | Mandatory | Text-gen, Voice-gen |
| **D002** | **Third-party testing for hallucinations** — Appoint expert third-parties to evaluate hallucinated outputs at least every 3 months | Mandatory | Text-gen, Voice-gen |
| **D003** | **Restrict unsafe tool calls** — Implement safeguards or technical controls to prevent tool calls in AI systems from executing unauthorized actions, accessing restricted information, or making decisions beyond their intended scope | Mandatory | Automation |
| **D004** | **Third-party testing of tool calls** — Appoint expert third-parties to evaluate tool calls in AI systems at least every 3 months | Mandatory | Automation |

---

### DOMAIN E — ACCOUNTABILITY
*Clear ownership, failure planning, governance, and supplier vetting*

| ID | Requirement | Status |
|----|------------|--------|
| **E001** | **AI failure plan for security breaches** — Document AI failure plan for AI privacy and security breaches, assigning accountable owners and establishing notification and remediation with third-party support as needed (legal, PR, insurers, etc.) | Mandatory |
| **E002** | **AI failure plan for harmful outputs** — Document an AI failure plan for harmful AI outputs that cause significant customer harm, assigning accountable owners and establishing remediation with third-party support as needed | Mandatory |
| **E003** | **AI failure plan for hallucinations** — Document AI failure plan for hallucinated AI outputs that cause substantial customer financial loss, assigning accountable owners and establishing remediation with third-party support as needed | Mandatory |
| **E004** | **Assign accountability** — Document which AI system changes across the development & deployment lifecycle require formal review or approval, assign a lead accountable for each, and document their approval with supporting evidence | Mandatory |
| **E005** | **Assess cloud vs on-prem processing** — Establish criteria for selecting cloud provider, and circumstances for on-premises processing considering data sensitivity, regulatory requirements, security controls, and operational needs | Mandatory |
| **E006** | **Conduct vendor due diligence** — Establish AI vendor due diligence processes for foundation and upstream model providers covering data handling, PII controls, security, and compliance | Mandatory |
| **E007** | **[Retired] Document system change approvals** | Retired |
| **E008** | **Review internal processes** — Establish regular internal reviews of key processes and document review records and approvals | Mandatory |
| **E009** | **Monitor third-party access** — Implement systems to monitor third-party access | Mandatory |
| **E010** | **Establish AI acceptable use policy** — Establish and implement an AI acceptable use policy | Mandatory |
| **E011** | **Record processing locations** — Document AI data processing locations | Mandatory |
| **E012** | **Document regulatory compliance** — Document applicable AI laws and standards, required data protections, and strategies for compliance | Mandatory |
| **E013** | **Implement quality management system** — Establish a quality management system for AI systems proportionate to the size of the organization | Mandatory |
| **E014** | **Share transparency reports** | Optional |
| **E015** | **Log model activity** — Maintain logs of AI system processes, actions, and model outputs where permitted to support incident investigation, auditing, and explanation of AI system behavior | Mandatory |
| **E016** | **Implement AI disclosure mechanisms** — Implement clear disclosure mechanisms to inform users when they are interacting with AI systems rather than humans | Mandatory |
| **E017** | **Document system transparency policy** — Establish a system transparency policy and maintain a repository of model cards, datasheets, and interpretability reports for major systems | Mandatory |

**E010 Control Detail (acceptable use policy):**
- Define prohibited AI usage for end-users: jailbreak attempts, malicious prompt injection, unauthorized data extraction, generation of harmful content, misuse of customer data (with specific examples)
- Implement detection and monitoring tools: prompt analysis, output filtering, usage pattern anomalies, suspicious access attempts
- Implement user feedback when policy is breached: alerts or error messages when inputs violate acceptable use
- Maintain logging and tracking systems, conduct regular effectiveness reviews

**E010 Crosswalks:** ISO 42001 (A.2.2, A.9.2, A.9.4, A.2.4, A.9.3, 4.1, 4.3, 5.2), NIST AI RMF (GOVERN 1.2, MAP 1.6, MAP 3.3, MAP 3.4, MEASURE 2.4), OWASP Top 10 (LLM10:25), CSA AICM (GRC-09)

---

### DOMAIN F — SOCIETY
*Prevent AI from enabling catastrophic societal harm*

| ID | Requirement | Status |
|----|------------|--------|
| **F001** | **Prevent AI cyber misuse** — Implement or document guardrails to prevent AI-enabled misuse for cyber-attacks and exploitation | Mandatory |
| **F002** | **Prevent catastrophic misuse** — Implement or document guardrails to prevent AI-enabled catastrophic system misuse (e.g. CBRN — chemical, biological, radiological, nuclear threats) | Mandatory |

---

## Evidence Framework

Every control activity is individually labeled, and typical evidence falls into **four categories**:

| Category | Description | Examples |
|----------|------------|---------|
| **Legal Policies** | Governance and policy documentation | Acceptable Use Policy, Data Retention Policy, Terms of Service, Privacy Policy |
| **Technical Implementation** | Code, configurations, and system screenshots | Engineering code for guardrails, input/output filtering configurations, access control settings, moderation tool configs |
| **Operational Practices** | Process documentation and internal reviews | Quarterly review records, incident response procedures, vendor due diligence records, training materials |
| **Third-Party Evals** | Independent testing results | Adversarial robustness testing reports, hallucination evaluation results, tool call testing results, harmful output testing reports |

Each evidence item has a **Typical Location** (e.g., "Engineering Code," "Product," "Policy Document," "Acceptable Use Policy") to guide where auditors look.

Organizations can submit **alternative evidence** demonstrating how they meet requirements if their approach differs from the typical evidence described.

---

## Certification Process

### Timeline: 4–8 weeks (typically)

| Phase | Duration | Activities | Outputs |
|-------|----------|-----------|---------|
| **Scoping & Kick-off** | 1–2 weeks | Define product scope, assign key team members, set up environment & config, identify initial evidence & gaps, sign contract | Audit & evals scoped; initial gaps identified |
| **Collect Evidence** | 3–5 weeks | Gather operational practices, legal/governance policies, technical implementation evidence; remediate gaps | Evidence collected; gaps remediated |
| **Conduct Evals** | Overlaps with evidence collection | Run technical testing: hallucinations, unsafe tool calls, adversarial attacks, harmful outputs, out-of-scope outputs | Evals set up & implemented; vulnerabilities mitigated |
| **Finalize Audit Report** | 1–3 weeks | Combine all evidence, develop final report, obtain signoff | Final audit report delivered; AIUC-1 certificate issued |

### What You Get

- **AIUC-1 Certificate** — communicates trust to enterprise buyers
- **Comprehensive Audit Report** — third-party attestation with detailed eval results
- **AIUC-1 Badge** — for trust center, footer, or sales collateral

### Ongoing Requirements

- **Quarterly (every 3 months):** Third-party technical testing re-run across safety, security, reliability domains
- **Annually:** Full re-certification with complete audit of all technical, operational, and legal controls
- **If not renewed:** Certificate is stale and must be removed (non-compliant)
- **Material issues:** Qualified/adverse report issued; P0/P1 vulnerabilities must be remediated for full certificate

### Certificate Comparison: AIUC-1 vs. SOC 2

| Dimension | AIUC-1 Technical | AIUC-1 Operational | SOC 2 Type II |
|-----------|-----------------|-------------------|---------------|
| Audit output | Audit report with certificate, exec summary, detailed technical testing and operational controls | — | Attestation report |
| Display term | 12 months | — | 12 months |
| Test cadence | At least quarterly | Annually | Annually |
| Forward-looking? | **Yes** — requires forward-looking policies and testing (log reviews, adversarial tests) | — | **No** — backward-looking assessment |
| Material issues | Re-testing required; P0/P1 must be remediated | Evidence must be provided | Only unqualified reports allow "SOC 2 compliant" claim |

---

## Scoping

Not all controls apply to every AI system. Scoping depends on:

- **Capabilities of the AI agent** — text generation, voice generation, image generation, automation/tool calls
- **AI architecture** — multimodal inputs/outputs, access to tool calls, sensitive data handling
- **Organizational ambition** — internal vs. external facing, risk appetite

A more powerful agent (e.g., with multimodal I/O, tool call access, or sensitive data) must meet a higher evidence bar. An internal-facing agent with limited data access needs fewer controls than an external customer service agent with access to sensitive data.

Organizations complete a **scoping questionnaire** with their accredited auditor to determine which requirements and control activities apply.

---

## Framework Crosswalks

AIUC-1 operationalizes and extends these major frameworks:

### ISO 42001
- Translates ISO's management system approach into concrete, auditable requirements
- Extends ISO 42001 with third-party testing requirements (hallucinations, jailbreak attempts)
- Addresses additional concerns like AI failure plans and AI-specific system security
- Following the newly introduced ISO 42006 standard closely

### NIST AI RMF
- Operationalizes NIST's four core functions (Govern, Map, Measure, Manage) into specific controls
- NIST provides the strategic foundation; AIUC-1 is the implementation and validation layer
- AIUC-1 includes 50+ controls vs. NIST's voluntary principles

### EU AI Act
- Enables compliance for minimal and limited risk systems
- Enables compliance for high risk systems if specific control activities are met
- Provides documentation for internal conformity assessments (Annex VI)

### MITRE ATLAS
- MITRE is a direct technical contributor
- Incorporates ATLAS mitigation strategies in requirements and controls
- Strengthens robustness against adversarial tactics and techniques identified in ATLAS

### OWASP Top 10 for LLM Applications
- Addresses all Top 10 LLM threats with concrete requirements and controls
- Goes beyond security to cover broader AI risk

### CSA AI Controls Matrix (AICM)
- Covers key AICM controls for AI vendors (adversarial robustness, system transparency, cloud vs on-prem)
- Avoids duplicating areas where CSA leads (data center infrastructure, physical security)

### What AIUC-1 Does NOT Duplicate
- **SOC 2** — general cybersecurity best practices
- **ISO 27001** — extends several controls into the AI domain (CIA triad) but doesn't replicate the full standard
- **GDPR** — does not duplicate data protection regulation
- **Regional regulations** — helps guide compliance with California SB 1001, Colorado AI Act, NYC Local Law 144 through optional requirements

---

## Accredited Auditors

**Schellman** is the first accredited auditor for AIUC-1, announced as a significant milestone for the AI compliance ecosystem.

---

## Certified Organizations (Examples)

- **ElevenLabs** — first voice AI company to achieve AIUC-1 certification
- **Intercom** — achieved AIUC-1 for their Fin AI Agent
- Other certified agents include: customer service agents, candidate scoring agents, interviewer agents, internal automation agents, image generation agents, summarization agents
- Organizations range from seed stage to publicly traded enterprises

---

## Real-World Impact (Reported Case Studies)

- A **customer service agent company** saw hallucination rates drop from 11% to <2% by strengthening its groundedness filter
- A **product onboarding agent company** discovered and patched a PII exposure vulnerability during certification
- A **customer support agent company** saw inappropriate tone & output format outputs reduce from 9% to <2% by strengthening defensive prompting and configuring output moderation

---

## Design Principles

| Principle | Description |
|-----------|------------|
| **Customer-focused** | Prioritizes requirements enterprise customers demand and vendors can pragmatically meet |
| **AI-focused** | Does not cover non-AI risks addressed by SOC 2, ISO 27001, or GDPR |
| **Insurance-enabling** | Emphasizes risks that lead to direct harms and financial losses |
| **Adaptable** | Updates as regulation, AI progress, and real-world deployment experience evolves |
| **Transparent** | Public changelog; lessons shared openly |
| **Forward-looking** | Requires at least quarterly testing to keep certificate relevant |
| **Predictable** | Quarterly update cadence (Jan 15, Apr 15, Jul 15, Oct 15) |

---

## Q1 2026 Update Highlights

The most recent quarterly update (Q1 2026) included:

- **26 requirements updated** — stronger PII protection in logs, threat modelling in pre-deployment testing, multimodal coverage of AI labelling, pickle-file security tools
- **Evidence requirements detailed** — control activities now individually labeled with typical evidence published
- **Scoping approach detailed** — capability-specific requirements now displayed; scoping questionnaire published
- **Certification process expanded** — more detail on becoming an accredited auditor
- **Readiness assessment** — organizations can download a spreadsheet version to self-assess gaps

---

## Summary: Total Control Count by Domain

| Domain | Mandatory | Optional | Total |
|--------|-----------|----------|-------|
| A. Data & Privacy | 7 | 0 | 7 |
| B. Security | 6 | 3 | 9 |
| C. Safety | 7 | 3 (+ 1 retired consideration) | 12 |
| D. Reliability | 4 | 0 | 4 |
| E. Accountability | ~15 | 1–2 | ~17 |
| F. Society | 2 | 0 | 2 |
| **TOTAL** | **~41** | **~7–8** | **~51** |

*Note: One Accountability requirement (E007) has been retired. Exact counts may vary slightly with quarterly updates.*

---

*Source: https://www.aiuc-1.com — crawled February 25, 2026*
