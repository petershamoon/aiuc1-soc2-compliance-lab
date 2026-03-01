# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Enforcement Layer
# ---------------------------------------------------------------------------
# Deterministic middleware that architecturally enforces AIUC-1 controls
# regardless of LLM behavior.  This is the "output gateway" pattern
# described in the README's Known Gaps section.
#
# The enforcement layer sits between the queue message handler and every
# function's output, guaranteeing that:
#
#   1. Every response is sanitised (A006/B009) — no prompt required
#   2. Scope boundaries are enforced (B006/D003) — blocked at infra layer
#   3. Tool-call restrictions are applied (D003/C007) — rate limits, blocks
#   4. AI disclosure is injected (E016) — infrastructure-level, not prompt
#   5. Every enforcement decision is cryptographically hashed (E015)
#   6. Policies are declarative and auditable (policy engine)
#
# This closes the "Prompt-Based vs. Architectural Enforcement" gap
# identified in the project README.
# ---------------------------------------------------------------------------

from .policy_engine import PolicyEngine, load_policies
from .gateway import OutputGateway
from .scope_enforcer import ScopeEnforcer
from .tool_restrictions import ToolRestrictionEngine
from .disclosure import DisclosureInjector
from .audit_chain import AuditChain
from .middleware import enforce
from .integration import enforced_write_output, check_input_enforcement

__all__ = [
    "PolicyEngine",
    "load_policies",
    "OutputGateway",
    "ScopeEnforcer",
    "ToolRestrictionEngine",
    "DisclosureInjector",
    "AuditChain",
    "enforce",
    "enforced_write_output",
    "check_input_enforcement",
]
