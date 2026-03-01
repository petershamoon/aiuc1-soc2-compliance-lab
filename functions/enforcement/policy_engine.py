# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Policy Engine
# ---------------------------------------------------------------------------
# Declarative, auditable policy definitions that map AIUC-1 controls to
# enforcement rules.  Policies are defined in code (not YAML) for type
# safety and zero-dependency deployment on Azure Functions Consumption plan.
#
# Each policy is a frozen dataclass that declares:
#   - Which AIUC-1 control(s) it enforces
#   - What action to take (block, sanitise, inject, log, rate_limit)
#   - Configuration parameters for the enforcement action
#   - Whether the policy is mandatory or optional
#
# The PolicyEngine evaluates all applicable policies for a given function
# call and returns an ordered list of enforcement actions.
#
# AIUC-1 Controls:
#   E015  Audit Trail     — every policy evaluation is logged
#   E017  Transparency    — policies are self-documenting
# ---------------------------------------------------------------------------

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("aiuc1.enforcement.policy")


class EnforcementAction(str, Enum):
    """Actions the enforcement layer can take."""
    SANITISE = "sanitise"
    BLOCK = "block"
    INJECT = "inject"
    LOG = "log"
    RATE_LIMIT = "rate_limit"
    REQUIRE_APPROVAL = "require_approval"


class PolicyScope(str, Enum):
    """Where in the request/response lifecycle the policy applies."""
    INPUT = "input"
    OUTPUT = "output"
    BOTH = "both"


@dataclass(frozen=True)
class EnforcementPolicy:
    """A single, immutable enforcement policy.

    Frozen dataclass prevents runtime mutation — policies are defined
    at module load and never change.  This is itself an AIUC-1 control:
    the enforcement rules cannot be modified by the LLM at runtime.
    """
    policy_id: str
    name: str
    description: str
    aiuc1_controls: tuple[str, ...]
    action: EnforcementAction
    scope: PolicyScope
    mandatory: bool = True
    applies_to: tuple[str, ...] = ()  # empty = all functions
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the policy definition for audit trail."""
        content = f"{self.policy_id}:{self.name}:{self.action.value}:{self.mandatory}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class EnforcementDecision:
    """The result of evaluating a policy against a function call.

    Every decision is immutable and includes a cryptographic hash
    for tamper-evident audit trails (AIUC-1 E015).
    """
    policy_id: str
    policy_name: str
    action: EnforcementAction
    applied: bool
    reason: str
    timestamp: str
    aiuc1_controls: tuple[str, ...]
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def decision_hash(self) -> str:
        """SHA-256 hash of the decision for chain-of-custody."""
        content = json.dumps({
            "policy_id": self.policy_id,
            "action": self.action.value,
            "applied": self.applied,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


class PolicyEngine:
    """Evaluates enforcement policies against function calls.

    The engine is initialised once at module load with the full set of
    policies.  At runtime, it filters applicable policies for a given
    function and returns ordered enforcement decisions.

    This is deterministic — the same input always produces the same
    decisions, regardless of what the LLM requested.
    """

    def __init__(self, policies: list[EnforcementPolicy]) -> None:
        self._policies = tuple(policies)
        self._by_function: dict[str, list[EnforcementPolicy]] = {}
        self._build_index()
        logger.info(
            "PolicyEngine initialised with %d policies (%d mandatory)",
            len(self._policies),
            sum(1 for p in self._policies if p.mandatory),
        )

    def _build_index(self) -> None:
        """Pre-compute per-function policy lookups."""
        for policy in self._policies:
            if not policy.applies_to:
                # Universal policy — applies to all functions
                self._by_function.setdefault("__all__", []).append(policy)
            else:
                for fn_name in policy.applies_to:
                    self._by_function.setdefault(fn_name, []).append(policy)

    def get_applicable_policies(
        self,
        function_name: str,
        scope: PolicyScope,
    ) -> list[EnforcementPolicy]:
        """Return all policies that apply to a function and scope.

        Args:
            function_name: Name of the Azure Function being called.
            scope: Whether we're evaluating input or output policies.

        Returns:
            Ordered list of applicable policies (mandatory first).
        """
        applicable = []
        # Universal policies
        for policy in self._by_function.get("__all__", []):
            if policy.scope in (scope, PolicyScope.BOTH):
                applicable.append(policy)
        # Function-specific policies
        for policy in self._by_function.get(function_name, []):
            if policy.scope in (scope, PolicyScope.BOTH):
                applicable.append(policy)
        # Mandatory policies first, then by policy_id for determinism
        applicable.sort(key=lambda p: (not p.mandatory, p.policy_id))
        return applicable

    def evaluate(
        self,
        function_name: str,
        scope: PolicyScope,
        context: dict[str, Any],
    ) -> list[EnforcementDecision]:
        """Evaluate all applicable policies and return decisions.

        This method does NOT execute the enforcement actions — it only
        determines which actions should be taken.  The middleware layer
        executes the decisions.

        Args:
            function_name: Name of the Azure Function.
            scope: Input or output evaluation.
            context: Runtime context (request body, response data, etc.).

        Returns:
            Ordered list of enforcement decisions.
        """
        policies = self.get_applicable_policies(function_name, scope)
        decisions = []
        now = datetime.now(timezone.utc).isoformat()

        for policy in policies:
            decision = self._evaluate_single(policy, function_name, context, now)
            decisions.append(decision)

        return decisions

    def _evaluate_single(
        self,
        policy: EnforcementPolicy,
        function_name: str,
        context: dict[str, Any],
        timestamp: str,
    ) -> EnforcementDecision:
        """Evaluate a single policy against the current context."""
        # Mandatory policies are always applied
        if policy.mandatory:
            return EnforcementDecision(
                policy_id=policy.policy_id,
                policy_name=policy.name,
                action=policy.action,
                applied=True,
                reason=f"Mandatory policy: {policy.description}",
                timestamp=timestamp,
                aiuc1_controls=policy.aiuc1_controls,
                details={"function": function_name, "config": policy.config},
            )

        # Optional policies may have conditional logic
        # For now, optional policies are applied if the function matches
        return EnforcementDecision(
            policy_id=policy.policy_id,
            policy_name=policy.name,
            action=policy.action,
            applied=True,
            reason=f"Optional policy applied: {policy.description}",
            timestamp=timestamp,
            aiuc1_controls=policy.aiuc1_controls,
            details={"function": function_name, "config": policy.config},
        )

    @property
    def policy_manifest(self) -> list[dict[str, Any]]:
        """Return a human-readable manifest of all policies.

        This supports AIUC-1 E017 (system transparency) by making the
        enforcement rules inspectable and auditable.
        """
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "aiuc1_controls": list(p.aiuc1_controls),
                "action": p.action.value,
                "scope": p.scope.value,
                "mandatory": p.mandatory,
                "applies_to": list(p.applies_to) or ["all"],
                "fingerprint": p.fingerprint,
            }
            for p in self._policies
        ]


# ---------------------------------------------------------------------------
# Default Policy Set — the AIUC-1 controls enforced architecturally
# ---------------------------------------------------------------------------

def load_policies() -> list[EnforcementPolicy]:
    """Load the default set of enforcement policies.

    These policies represent the architectural enforcement of AIUC-1
    controls.  They cannot be overridden by the LLM at runtime.
    """
    return [
        # ---- OUTPUT SANITISATION (A006/B009) ----
        EnforcementPolicy(
            policy_id="ENF-001",
            name="Mandatory Output Sanitisation",
            description=(
                "Every function response is sanitised to redact subscription IDs, "
                "access keys, connection strings, private IPs, SAS tokens, and "
                "bearer tokens.  Applied at the infrastructure layer — the LLM "
                "cannot bypass this by skipping the sanitize_output tool call."
            ),
            aiuc1_controls=("A006", "B009", "A004"),
            action=EnforcementAction.SANITISE,
            scope=PolicyScope.OUTPUT,
            mandatory=True,
        ),

        # ---- SCOPE BOUNDARY ENFORCEMENT (B006) ----
        EnforcementPolicy(
            policy_id="ENF-002",
            name="Resource Group Scope Boundary",
            description=(
                "All function inputs are validated to ensure resource group "
                "references stay within the three allowed lab resource groups. "
                "Requests targeting out-of-scope resources are blocked before "
                "reaching Azure APIs."
            ),
            aiuc1_controls=("B006", "D003"),
            action=EnforcementAction.BLOCK,
            scope=PolicyScope.INPUT,
            mandatory=True,
            config={
                "allowed_resource_groups": [
                    "rg-aiuc1-foundry",
                    "rg-production",
                    "rg-development",
                ],
            },
        ),

        # ---- TOOL-CALL RESTRICTIONS (D003) ----
        EnforcementPolicy(
            policy_id="ENF-003",
            name="Destructive Operation Block",
            description=(
                "Terraform operations containing destructive patterns "
                "(destroy, role assignments, management groups, policy exemptions) "
                "are blocked at the function layer before execution."
            ),
            aiuc1_controls=("D003", "C007", "B006"),
            action=EnforcementAction.BLOCK,
            scope=PolicyScope.INPUT,
            mandatory=True,
            applies_to=("run_terraform_plan", "run_terraform_apply"),
            config={
                "blocked_patterns": [
                    "azurerm_role_assignment",
                    "azurerm_management_group",
                    "azurerm_subscription",
                    "azurerm_policy_exemption",
                    "destroy",
                ],
            },
        ),

        # ---- HUMAN-IN-THE-LOOP GATE (C007) ----
        EnforcementPolicy(
            policy_id="ENF-004",
            name="Terraform Apply Approval Gate",
            description=(
                "run_terraform_apply physically cannot execute without a valid "
                "HMAC approval token generated by run_terraform_plan.  This is "
                "architectural enforcement — the function rejects the call at "
                "the crypto layer, not the prompt layer."
            ),
            aiuc1_controls=("C007", "E004"),
            action=EnforcementAction.REQUIRE_APPROVAL,
            scope=PolicyScope.INPUT,
            mandatory=True,
            applies_to=("run_terraform_apply",),
            config={
                "token_algorithm": "HMAC-SHA256",
                "token_field": "approval_token",
                "hash_field": "plan_hash",
            },
        ),

        # ---- AI DISCLOSURE INJECTION (E016) ----
        EnforcementPolicy(
            policy_id="ENF-005",
            name="AI Disclosure Footer Injection",
            description=(
                "Every function response includes an AI disclosure footer "
                "injected at the infrastructure layer.  The LLM does not need "
                "to remember to add it — the enforcement layer guarantees it."
            ),
            aiuc1_controls=("E016",),
            action=EnforcementAction.INJECT,
            scope=PolicyScope.OUTPUT,
            mandatory=True,
            config={
                "footer_text": (
                    "This output was processed by the AIUC-1 enforcement layer. "
                    "All data has been sanitised and validated against AIUC-1 controls. "
                    "This assessment was generated by an AI agent and should be reviewed "
                    "by a qualified human auditor."
                ),
            },
        ),

        # ---- AUDIT LOGGING (E015) ----
        EnforcementPolicy(
            policy_id="ENF-006",
            name="Enforcement Audit Trail",
            description=(
                "Every enforcement decision (block, sanitise, inject) is logged "
                "with a cryptographic hash for tamper-evident chain of custody. "
                "This runs at the infrastructure layer — the LLM cannot suppress "
                "audit logging by skipping the log_security_event tool call."
            ),
            aiuc1_controls=("E015", "E017"),
            action=EnforcementAction.LOG,
            scope=PolicyScope.BOTH,
            mandatory=True,
        ),

        # ---- RATE LIMITING (B004/B006) ----
        EnforcementPolicy(
            policy_id="ENF-007",
            name="Tool Call Rate Limiting",
            description=(
                "Prevents rapid-fire tool calls that could indicate adversarial "
                "probing or endpoint scraping.  Each function is limited to a "
                "configurable number of calls per time window."
            ),
            aiuc1_controls=("B004", "B006"),
            action=EnforcementAction.RATE_LIMIT,
            scope=PolicyScope.INPUT,
            mandatory=True,
            config={
                "max_calls_per_minute": 30,
                "max_calls_per_hour": 500,
                "cooldown_seconds": 2,
            },
        ),

        # ---- INPUT SANITISATION (A003/C006) ----
        EnforcementPolicy(
            policy_id="ENF-008",
            name="Input Payload Sanitisation",
            description=(
                "Input payloads are scanned for injection patterns including "
                "shell metacharacters, SQL injection fragments, and script tags. "
                "Malicious inputs are blocked before reaching function logic."
            ),
            aiuc1_controls=("A003", "C006", "B001"),
            action=EnforcementAction.SANITISE,
            scope=PolicyScope.INPUT,
            mandatory=True,
            config={
                "blocked_input_patterns": [
                    r"<script",
                    r"javascript:",
                    r";\s*(?:rm|del|drop|truncate|exec)\s",
                    r"\$\{.*\}",
                    r"__import__",
                    r"eval\s*\(",
                    r"os\.system",
                ],
            },
        ),

        # ---- GIT COMMIT SECRET SCANNING (A004) ----
        EnforcementPolicy(
            policy_id="ENF-009",
            name="Pre-Commit Secret Scanning",
            description=(
                "git_commit_push runs a mandatory secret scan before any commit. "
                "Files containing potential credentials are blocked from being "
                "committed to the repository."
            ),
            aiuc1_controls=("A004", "B009"),
            action=EnforcementAction.BLOCK,
            scope=PolicyScope.INPUT,
            mandatory=True,
            applies_to=("git_commit_push",),
            config={
                "scan_patterns": [
                    r"(?:password|secret|key|token)\s*[=:]\s*['\"][^'\"]{8,}",
                    r"DefaultEndpointsProtocol=",
                    r"[A-Za-z0-9+/]{40,}={0,2}",
                    r"sk-[A-Za-z0-9]{20,}",
                    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
                ],
            },
        ),

        # ---- ALLOWED DIRECTORY ENFORCEMENT (B006) ----
        EnforcementPolicy(
            policy_id="ENF-010",
            name="Git Commit Path Restriction",
            description=(
                "git_commit_push only allows commits to whitelisted directories. "
                "Attempts to commit to system directories or configuration files "
                "are blocked at the enforcement layer."
            ),
            aiuc1_controls=("B006", "D003"),
            action=EnforcementAction.BLOCK,
            scope=PolicyScope.INPUT,
            mandatory=True,
            applies_to=("git_commit_push",),
            config={
                "allowed_directories": [
                    "reports",
                    "docs",
                    "terraform",
                    "policies",
                    "evidence",
                ],
            },
        ),
    ]
