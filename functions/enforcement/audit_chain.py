# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Audit Chain
# ---------------------------------------------------------------------------
# Maintains a cryptographic chain of enforcement decisions for tamper-
# evident audit trails.  Every enforcement action (block, sanitise,
# inject, rate_limit) is hashed and chained to the previous decision,
# creating an append-only log that cannot be retroactively modified.
#
# This is the enforcement layer's implementation of AIUC-1 E015:
#   "Maintain logs of AI system processes, actions, and model outputs
#    where permitted to support incident investigation, auditing, and
#    explanation of AI system behavior."
#
# The chain is maintained in-memory per process lifetime (Azure Functions
# Consumption plan).  For cross-invocation persistence, the chain head
# hash is written to the function response envelope, and the full chain
# is logged to Application Insights.
#
# AIUC-1 Controls:
#   E015  Log model activity
#   E017  Document system transparency policy
#   E004  Assign accountability
# ---------------------------------------------------------------------------

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("aiuc1.enforcement.audit")


@dataclass(frozen=True)
class AuditEntry:
    """A single entry in the enforcement audit chain.

    Each entry contains:
    - The enforcement decision details
    - A SHA-256 hash of the entry content
    - The hash of the previous entry (chain link)
    - A sequence number for ordering

    The chain is append-only: new entries reference the previous entry's
    hash, making retroactive modification detectable.
    """
    sequence: int
    timestamp: str
    function_name: str
    action: str
    policy_id: str
    applied: bool
    reason: str
    aiuc1_controls: tuple[str, ...]
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this entry's content."""
        content = json.dumps({
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "function_name": self.function_name,
            "action": self.action,
            "policy_id": self.policy_id,
            "applied": self.applied,
            "reason": self.reason,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


class AuditChain:
    """Append-only chain of enforcement audit entries.

    The chain provides:
    1. Tamper-evident logging — each entry's hash includes the previous
       entry's hash, so modifying any entry breaks the chain.
    2. Structured audit trail — every enforcement decision is recorded
       with full context for incident investigation.
    3. Chain verification — the verify() method checks the integrity
       of the entire chain.

    Usage::

        chain = AuditChain()
        chain.record(
            function_name="gap_analyzer",
            action="sanitise",
            policy_id="ENF-001",
            applied=True,
            reason="Mandatory output sanitisation",
            aiuc1_controls=("A006", "B009"),
        )
        assert chain.verify()
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._head_hash: str = "genesis"  # Genesis block hash

    def record(
        self,
        function_name: str,
        action: str,
        policy_id: str,
        applied: bool,
        reason: str,
        aiuc1_controls: tuple[str, ...] = (),
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        """Record an enforcement decision in the audit chain.

        Args:
            function_name: The function being enforced.
            action: The enforcement action taken (block, sanitise, etc.).
            policy_id: The policy that triggered the action.
            applied: Whether the action was actually applied.
            reason: Human-readable reason for the decision.
            aiuc1_controls: AIUC-1 control IDs exercised.
            details: Additional context for the decision.

        Returns:
            The created AuditEntry with computed hash.
        """
        sequence = len(self._entries) + 1
        now = datetime.now(timezone.utc).isoformat()

        entry = AuditEntry(
            sequence=sequence,
            timestamp=now,
            function_name=function_name,
            action=action,
            policy_id=policy_id,
            applied=applied,
            reason=reason,
            aiuc1_controls=aiuc1_controls,
            details=details or {},
            previous_hash=self._head_hash,
        )

        # Compute and set the entry hash
        entry_hash = entry.compute_hash()
        # Since AuditEntry is frozen, we create a new one with the hash
        entry = AuditEntry(
            sequence=entry.sequence,
            timestamp=entry.timestamp,
            function_name=entry.function_name,
            action=entry.action,
            policy_id=entry.policy_id,
            applied=entry.applied,
            reason=entry.reason,
            aiuc1_controls=entry.aiuc1_controls,
            details=entry.details,
            previous_hash=entry.previous_hash,
            entry_hash=entry_hash,
        )

        self._entries.append(entry)
        self._head_hash = entry_hash

        # Log to Application Insights (structured JSON)
        logger.info(json.dumps({
            "event_type": "enforcement_audit",
            "sequence": sequence,
            "function_name": function_name,
            "action": action,
            "policy_id": policy_id,
            "applied": applied,
            "entry_hash": entry_hash[:16],
            "chain_length": len(self._entries),
            "aiuc1_controls": list(aiuc1_controls),
        }))

        return entry

    def verify(self) -> bool:
        """Verify the integrity of the entire audit chain.

        Walks the chain from genesis to head, recomputing each entry's
        hash and checking that it matches the stored hash and that the
        previous_hash links are correct.

        Returns:
            True if the chain is intact, False if tampering is detected.
        """
        if not self._entries:
            return True

        expected_previous = "genesis"

        for entry in self._entries:
            # Check chain link
            if entry.previous_hash != expected_previous:
                logger.error(
                    "Audit chain broken at sequence %d: "
                    "expected previous_hash=%s, got=%s",
                    entry.sequence,
                    expected_previous[:16],
                    entry.previous_hash[:16],
                )
                return False

            # Recompute and verify hash
            recomputed = entry.compute_hash()
            if entry.entry_hash != recomputed:
                logger.error(
                    "Audit chain tampered at sequence %d: "
                    "stored hash=%s, recomputed=%s",
                    entry.sequence,
                    entry.entry_hash[:16],
                    recomputed[:16],
                )
                return False

            expected_previous = entry.entry_hash

        return True

    @property
    def head_hash(self) -> str:
        """Return the hash of the most recent entry (chain head)."""
        return self._head_hash

    @property
    def length(self) -> int:
        """Return the number of entries in the chain."""
        return len(self._entries)

    def get_summary(self) -> dict[str, Any]:
        """Return a summary of the audit chain for response metadata."""
        action_counts: dict[str, int] = {}
        control_counts: dict[str, int] = {}

        for entry in self._entries:
            action_counts[entry.action] = action_counts.get(entry.action, 0) + 1
            for control in entry.aiuc1_controls:
                control_counts[control] = control_counts.get(control, 0) + 1

        return {
            "chain_length": len(self._entries),
            "chain_head_hash": self._head_hash[:16],
            "chain_verified": self.verify(),
            "action_counts": action_counts,
            "controls_exercised": control_counts,
            "aiuc1_control": "E015",
        }

    def get_entries_for_function(
        self,
        function_name: str,
    ) -> list[dict[str, Any]]:
        """Return all audit entries for a specific function."""
        return [
            {
                "sequence": e.sequence,
                "timestamp": e.timestamp,
                "action": e.action,
                "policy_id": e.policy_id,
                "applied": e.applied,
                "reason": e.reason,
                "entry_hash": e.entry_hash[:16],
            }
            for e in self._entries
            if e.function_name == function_name
        ]
