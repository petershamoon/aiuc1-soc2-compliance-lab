# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Tool Restriction Engine
# ---------------------------------------------------------------------------
# Enforces tool-call restrictions at the infrastructure layer:
#
#   1. Rate limiting — prevents adversarial probing / endpoint scraping
#   2. Blocked input patterns — rejects injection attempts
#   3. Action classification — categorises tool calls by risk level
#   4. Approval validation — verifies HMAC tokens for high-risk actions
#
# Rate limiting is designed to be agent-friendly: the cooldown is
# per-function (not global), and the thresholds are generous enough
# for normal multi-tool workflows while still catching runaway loops
# and adversarial probing.
#
# AIUC-1 Controls:
#   D003  Restrict unsafe tool calls
#   C007  Flag high-risk outputs (human-in-the-loop)
#   B004  Prevent AI endpoint scraping (rate limiting)
#   B006  Prevent unauthorized AI agent actions
#   C006  Prevent output vulnerabilities (input sanitisation)
# ---------------------------------------------------------------------------

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("aiuc1.enforcement.restrictions")


class RiskLevel(str, Enum):
    """Risk classification for tool calls (AIUC-1 C001)."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---- Tool Risk Classification ----

_TOOL_RISK_MAP: dict[str, RiskLevel] = {
    # Data providers — read-only, low risk
    "gap_analyzer": RiskLevel.LOW,
    "scan_cc_criteria": RiskLevel.LOW,
    "evidence_validator": RiskLevel.LOW,
    "query_access_controls": RiskLevel.LOW,
    "query_defender_score": RiskLevel.LOW,
    "query_policy_compliance": RiskLevel.LOW,
    # Action functions — write operations, higher risk
    "generate_poam_entry": RiskLevel.MEDIUM,
    "git_commit_push": RiskLevel.MEDIUM,
    "run_terraform_plan": RiskLevel.HIGH,
    "run_terraform_apply": RiskLevel.CRITICAL,
    # Safety functions — internal, low risk
    "sanitize_output": RiskLevel.LOW,
    "log_security_event": RiskLevel.LOW,
}


# ---- Input Injection Patterns ----

_INJECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r";\s*(?:rm|del|drop|truncate|exec)\s", re.IGNORECASE),
    re.compile(r"\$\{.*\}"),
    re.compile(r"__import__"),
    re.compile(r"eval\s*\("),
    re.compile(r"os\.system"),
    re.compile(r"subprocess\."),
    re.compile(r";\s*--"),  # SQL comment injection
    re.compile(r"'\s*(?:OR|AND)\s+\d+\s*=\s*\d+", re.IGNORECASE),  # SQL injection
]

# Fields that contain code/templates and should skip injection scanning.
# Terraform HCL, policy JSON, and git diffs legitimately contain patterns
# that look like injections (e.g., ${var.subscription_id}).
_INJECTION_EXEMPT_FIELDS = frozenset({
    "terraform_content",
    "hcl_content",
    "policy_rule",
    "policy_json",
    "file_content",
    "diff",
    "template",
    "main_tf",
    "variables_tf",
})

# Functions whose payloads may contain code/templates and should have
# relaxed injection scanning (only scan explicit user-input fields).
_INJECTION_RELAXED_FUNCTIONS = frozenset({
    "run_terraform_plan",
    "run_terraform_apply",
    "git_commit_push",
    "generate_poam_entry",
})


@dataclass
class RestrictionViolation:
    """A detected tool-call restriction violation."""
    rule: str
    description: str
    severity: str
    aiuc1_controls: list[str]
    details: dict[str, Any] = field(default_factory=dict)


class ToolRestrictionEngine:
    """Enforces tool-call restrictions at the infrastructure layer.

    Rate Limiting:
        Uses a per-function sliding window.  The cooldown is short (0.5s)
        to allow normal agent workflows where multiple different functions
        are called in sequence.  The per-minute and per-hour limits catch
        runaway loops and adversarial probing.

    Input Scanning:
        Scans input payloads for injection patterns.  Functions that
        handle code/templates (Terraform, git) have relaxed scanning
        that skips known code fields.

    Approval Validation:
        Critical functions (run_terraform_apply) require a valid HMAC
        approval token.  The engine validates the token cryptographically
        before allowing execution (C007).
    """

    def __init__(
        self,
        max_calls_per_minute: int = 30,
        max_calls_per_hour: int = 500,
        cooldown_seconds: float = 0.5,
    ) -> None:
        self._max_per_minute = max_calls_per_minute
        self._max_per_hour = max_calls_per_hour
        self._cooldown = cooldown_seconds
        # Per-function call timestamps for rate limiting
        self._call_log: dict[str, list[float]] = defaultdict(list)
        self._last_call: dict[str, float] = {}

    def check_restrictions(
        self,
        function_name: str,
        payload: dict[str, Any],
    ) -> list[RestrictionViolation]:
        """Check all restrictions for a function call.

        Args:
            function_name: Name of the target function.
            payload: The parsed input payload.

        Returns:
            List of violations (empty if all checks pass).
        """
        violations = []

        # 1. Rate limiting (per-function cooldown)
        rate_violation = self._check_rate_limit(function_name)
        if rate_violation:
            violations.append(rate_violation)

        # 2. Input injection scanning (with exemptions for code fields)
        injection_violations = self._scan_for_injections(function_name, payload)
        violations.extend(injection_violations)

        # 3. Approval token validation (for critical functions)
        if _TOOL_RISK_MAP.get(function_name) == RiskLevel.CRITICAL:
            approval_violation = self._check_approval_token(function_name, payload)
            if approval_violation:
                violations.append(approval_violation)

        # Record the call (even if blocked, for rate tracking)
        self._record_call(function_name)

        return violations

    def _check_rate_limit(
        self,
        function_name: str,
    ) -> Optional[RestrictionViolation]:
        """Check if the function call exceeds rate limits."""
        now = time.monotonic()

        # Per-function cooldown check
        last = self._last_call.get(function_name, 0)
        if now - last < self._cooldown:
            return RestrictionViolation(
                rule="rate_limit_cooldown",
                description=(
                    f"Function '{function_name}' called within cooldown period "
                    f"({self._cooldown}s).  Minimum interval between calls enforced."
                ),
                severity="WARNING",
                aiuc1_controls=["B004", "B006"],
                details={
                    "cooldown_seconds": self._cooldown,
                    "time_since_last_call": round(now - last, 2),
                },
            )

        # Per-minute check
        timestamps = self._call_log[function_name]
        minute_ago = now - 60
        recent_calls = [t for t in timestamps if t > minute_ago]
        if len(recent_calls) >= self._max_per_minute:
            return RestrictionViolation(
                rule="rate_limit_per_minute",
                description=(
                    f"Function '{function_name}' exceeded {self._max_per_minute} "
                    f"calls/minute.  Rate limit enforced to prevent endpoint scraping."
                ),
                severity="ERROR",
                aiuc1_controls=["B004", "B006"],
                details={
                    "calls_in_last_minute": len(recent_calls),
                    "limit": self._max_per_minute,
                },
            )

        # Per-hour check
        hour_ago = now - 3600
        hourly_calls = [t for t in timestamps if t > hour_ago]
        if len(hourly_calls) >= self._max_per_hour:
            return RestrictionViolation(
                rule="rate_limit_per_hour",
                description=(
                    f"Function '{function_name}' exceeded {self._max_per_hour} "
                    f"calls/hour.  Hourly rate limit enforced."
                ),
                severity="ERROR",
                aiuc1_controls=["B004", "B006"],
                details={
                    "calls_in_last_hour": len(hourly_calls),
                    "limit": self._max_per_hour,
                },
            )

        return None

    def _scan_for_injections(
        self,
        function_name: str,
        payload: dict[str, Any],
    ) -> list[RestrictionViolation]:
        """Scan input payload for injection patterns.

        Functions in _INJECTION_RELAXED_FUNCTIONS skip scanning on
        fields listed in _INJECTION_EXEMPT_FIELDS, since those fields
        legitimately contain code/template content.
        """
        violations = []
        relaxed = function_name in _INJECTION_RELAXED_FUNCTIONS
        flat_values = self._flatten_values(payload)

        for field_path, value in flat_values:
            if not isinstance(value, str):
                continue

            # Skip exempt fields for relaxed functions
            if relaxed:
                field_name = field_path.rsplit(".", 1)[-1].lower()
                if field_name in _INJECTION_EXEMPT_FIELDS:
                    continue

            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(value)
                if match:
                    violations.append(RestrictionViolation(
                        rule="input_injection_detected",
                        description=(
                            f"Potential injection pattern detected in field "
                            f"'{field_path}' of '{function_name}'.  "
                            f"Pattern: {pattern.pattern[:50]}"
                        ),
                        severity="CRITICAL",
                        aiuc1_controls=["C006", "B001", "A003"],
                        details={
                            "field": field_path,
                            "pattern": pattern.pattern[:50],
                            "match_preview": match.group(0)[:30],
                        },
                    ))
                    break  # One violation per field is enough

        return violations

    def _check_approval_token(
        self,
        function_name: str,
        payload: dict[str, Any],
    ) -> Optional[RestrictionViolation]:
        """Validate HMAC approval token for critical functions."""
        plan_hash = payload.get("plan_hash", "").strip()
        approval_token = payload.get("approval_token", "").strip()

        if not plan_hash or not approval_token:
            return RestrictionViolation(
                rule="missing_approval_token",
                description=(
                    f"Critical function '{function_name}' requires both "
                    f"plan_hash and approval_token.  AIUC-1 C007 mandates "
                    f"human approval for high-risk operations."
                ),
                severity="CRITICAL",
                aiuc1_controls=["C007", "E004"],
                details={"has_plan_hash": bool(plan_hash), "has_token": bool(approval_token)},
            )

        # Validate the HMAC token
        secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
        expected = hmac.new(
            secret.encode(), plan_hash.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(approval_token, expected):
            return RestrictionViolation(
                rule="invalid_approval_token",
                description=(
                    f"Invalid HMAC approval token for '{function_name}'.  "
                    f"The token does not match the plan hash.  This could "
                    f"indicate a replay attack or token tampering."
                ),
                severity="CRITICAL",
                aiuc1_controls=["C007", "E004", "B001"],
                details={"plan_hash_prefix": plan_hash[:8]},
            )

        return None

    def _record_call(self, function_name: str) -> None:
        """Record a function call timestamp for rate limiting."""
        now = time.monotonic()
        self._last_call[function_name] = now
        self._call_log[function_name].append(now)
        # Prune old entries (older than 1 hour)
        hour_ago = now - 3600
        self._call_log[function_name] = [
            t for t in self._call_log[function_name] if t > hour_ago
        ]

    def _flatten_values(
        self,
        obj: Any,
        path: str = "",
    ) -> list[tuple[str, Any]]:
        """Flatten a nested dict/list into (path, value) pairs."""
        results = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                results.extend(self._flatten_values(value, new_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                results.extend(self._flatten_values(item, f"{path}[{i}]"))
        else:
            results.append((path, obj))
        return results

    @staticmethod
    def get_risk_level(function_name: str) -> RiskLevel:
        """Return the risk classification for a function."""
        return _TOOL_RISK_MAP.get(function_name, RiskLevel.MEDIUM)

    @staticmethod
    def get_risk_map() -> dict[str, str]:
        """Return the full risk classification map (for transparency)."""
        return {k: v.value for k, v in _TOOL_RISK_MAP.items()}
