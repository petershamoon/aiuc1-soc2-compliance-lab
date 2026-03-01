# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Scope Enforcer
# ---------------------------------------------------------------------------
# Architectural enforcement of resource group boundaries.  This module
# scans every input payload for resource group references and blocks
# any that fall outside the allowed lab scope.
#
# The enforcer distinguishes between:
#   - READ scope  — resource groups the agent is allowed to QUERY/AUDIT
#   - WRITE scope — resource groups the agent is allowed to MODIFY
#
# Read scope is intentionally broad (the agent needs to audit production
# and development environments).  Write scope is tight (the agent can
# only make changes within the lab infrastructure).
#
# Certain functions (Terraform, git) are exempt from scope scanning on
# their content fields because they legitimately contain references to
# external resource groups in policy definitions and IaC templates.
#
# AIUC-1 Controls:
#   B006  Prevent unauthorized AI agent actions
#   D003  Restrict unsafe tool calls
#   A003  Limit AI agent data collection
# ---------------------------------------------------------------------------

from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger("aiuc1.enforcement.scope")

# ---------------------------------------------------------------------------
# Scope Definitions
# ---------------------------------------------------------------------------

# READ scope — resource groups the agent can query and audit.
# The agent's job is to scan these environments for SOC 2 compliance.
_DEFAULT_READ_SCOPE = frozenset({
    "rg-aiuc1-foundry",
    "rg-aiuc1-agents",
    "rg-production",
    "rg-development",
})

# WRITE scope — resource groups the agent can modify (deploy, remediate).
# Only the lab's own infrastructure is writable.
_DEFAULT_WRITE_SCOPE = frozenset({
    "rg-aiuc1-foundry",
    "rg-aiuc1-agents",
})

# Functions that operate on content (Terraform HCL, git diffs, policy JSON)
# which legitimately references external resource groups.  These functions
# are exempt from deep content scanning but still subject to the explicit
# resource_group field check.
_CONTENT_EXEMPT_FUNCTIONS = frozenset({
    "run_terraform_plan",
    "run_terraform_apply",
    "git_commit_push",
    "generate_poam_entry",
    "sanitize_output",
})

# Write-operation functions — these use write scope instead of read scope.
_WRITE_FUNCTIONS = frozenset({
    "run_terraform_plan",
    "run_terraform_apply",
    "git_commit_push",
})

# Patterns that might contain resource group references in payloads
_RG_FIELD_NAMES = frozenset({
    "resource_group",
    "resourcegroup",
    "rg",
    "target_rg",
})

# ARM resource ID pattern: /subscriptions/.../resourceGroups/<name>/...
_ARM_RG_PATTERN = re.compile(
    r"/resourceGroups/([^/]+)",
    re.IGNORECASE,
)


class ScopeViolation:
    """Represents a detected scope boundary violation."""

    def __init__(
        self,
        field: str,
        value: str,
        resource_group: str,
        reason: str,
    ) -> None:
        self.field = field
        self.value = value
        self.resource_group = resource_group
        self.reason = reason

    def to_dict(self) -> dict[str, str]:
        return {
            "field": self.field,
            "value": self.value,
            "resource_group": self.resource_group,
            "reason": self.reason,
        }


class ScopeEnforcer:
    """Enforces resource group scope boundaries on input payloads.

    The enforcer uses a two-tier scope model:

    - **Read scope** (default): Allows querying/auditing a broad set of
      resource groups.  This is the scope used by data-provider functions
      like ``query_access_controls`` and ``query_defender_score``.

    - **Write scope**: Restricts modifications to the lab's own
      infrastructure.  Used by ``run_terraform_apply``, ``git_commit_push``.

    Content-exempt functions (Terraform, git, POA&M) skip deep content
    scanning because their payloads legitimately contain references to
    external resource groups in policy definitions and templates.
    """

    def __init__(
        self,
        read_scope: Optional[frozenset[str]] = None,
        write_scope: Optional[frozenset[str]] = None,
    ) -> None:
        self._read_scope = read_scope or _DEFAULT_READ_SCOPE
        self._write_scope = write_scope or _DEFAULT_WRITE_SCOPE
        logger.info(
            "ScopeEnforcer initialised — read scope: %s, write scope: %s",
            sorted(self._read_scope),
            sorted(self._write_scope),
        )

    def check_payload(
        self,
        payload: dict[str, Any],
        function_name: str,
    ) -> list[ScopeViolation]:
        """Scan an input payload for scope violations.

        Args:
            payload: The parsed JSON input from the queue message.
            function_name: Name of the target function.

        Returns:
            List of ScopeViolation objects (empty if clean).
        """
        violations = []

        # Determine which scope to use based on the function
        if function_name in _WRITE_FUNCTIONS:
            allowed = self._write_scope
            scope_label = "write"
        else:
            allowed = self._read_scope
            scope_label = "read"

        # Content-exempt functions only check explicit RG fields
        content_exempt = function_name in _CONTENT_EXEMPT_FUNCTIONS

        self._scan_dict(payload, "", violations, allowed, scope_label, content_exempt)

        if violations:
            logger.warning(
                "ScopeEnforcer blocked %d violation(s) in %s (%s scope): %s",
                len(violations),
                function_name,
                scope_label,
                [v.resource_group for v in violations],
            )

        return violations

    def _scan_dict(
        self,
        obj: dict[str, Any],
        path: str,
        violations: list[ScopeViolation],
        allowed: frozenset[str],
        scope_label: str,
        content_exempt: bool,
    ) -> None:
        """Recursively scan a dictionary for scope violations."""
        for key, value in obj.items():
            field_path = f"{path}.{key}" if path else key

            if isinstance(value, str):
                self._check_string_value(
                    key, value, field_path, violations,
                    allowed, scope_label, content_exempt,
                )
            elif isinstance(value, dict):
                self._scan_dict(
                    value, field_path, violations,
                    allowed, scope_label, content_exempt,
                )
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        self._check_string_value(
                            key, item, f"{field_path}[{i}]", violations,
                            allowed, scope_label, content_exempt,
                        )
                    elif isinstance(item, dict):
                        self._scan_dict(
                            item, f"{field_path}[{i}]", violations,
                            allowed, scope_label, content_exempt,
                        )

    def _check_string_value(
        self,
        key: str,
        value: str,
        field_path: str,
        violations: list[ScopeViolation],
        allowed: frozenset[str],
        scope_label: str,
        content_exempt: bool,
    ) -> None:
        """Check a single string value for scope violations."""
        key_lower = key.lower().replace("-", "_").replace(" ", "_")

        # Check explicit resource group fields (always checked, even for
        # content-exempt functions)
        if key_lower in _RG_FIELD_NAMES:
            rg_name = value.strip()
            if rg_name and rg_name not in allowed:
                violations.append(ScopeViolation(
                    field=field_path,
                    value=value,
                    resource_group=rg_name,
                    reason=(
                        f"Resource group '{rg_name}' is outside the allowed "
                        f"{scope_label} scope.  Allowed: {sorted(allowed)}.  "
                        f"AIUC-1 B006 violation."
                    ),
                ))

        # Check for embedded ARM resource IDs in non-exempt content
        if not content_exempt:
            for match in _ARM_RG_PATTERN.finditer(value):
                rg_name = match.group(1)
                if rg_name not in allowed:
                    violations.append(ScopeViolation(
                        field=field_path,
                        value=value[:100],  # Truncate for logging
                        resource_group=rg_name,
                        reason=(
                            f"ARM resource ID references resource group "
                            f"'{rg_name}' which is outside the allowed "
                            f"{scope_label} scope.  AIUC-1 B006 violation."
                        ),
                    ))

    @property
    def allowed_resource_groups(self) -> frozenset[str]:
        """Return the read scope (broadest allowed set) for transparency."""
        return self._read_scope

    @property
    def write_scope(self) -> frozenset[str]:
        """Return the write scope for transparency."""
        return self._write_scope
