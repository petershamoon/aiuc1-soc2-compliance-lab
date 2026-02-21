# ADR-003: Single-Tenant Architecture

**Status**: Accepted

**Control**: AIUC-1 A005 (Prevent cross-customer data exposure)

**Context**: The AIUC-1 Compliance Lab project processes Azure resource configuration data. A decision must be made about whether to use a shared, multi-tenant architecture or a dedicated, single-tenant architecture for the agent infrastructure.

**Decision**: The project will use a **single-tenant architecture**. All Azure resources, including the AI Foundry hub, Azure Functions, and target infrastructure, are deployed within a single, dedicated Azure subscription owned and controlled solely by Pete.

**Rationale**: A single-tenant architecture is the most straightforward way to satisfy AIUC-1 control A005, which requires preventing cross-customer data exposure. Since all resources exist within a single subscription with a single owner, there is no possibility of data from one "customer" being exposed to another. This also simplifies the IAM model, as there is only one principal (Pete) with Owner-level access.

**Consequences**: This architecture is not suitable for a production SaaS product, but it is entirely appropriate for this single-user portfolio and compliance lab project.
