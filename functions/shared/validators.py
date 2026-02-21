# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Input Validators
# ---------------------------------------------------------------------------
# Validates inputs before they reach Azure SDK calls.  This is the first
# line of defence against prompt-injection attacks where a malicious agent
# prompt might try to query resources outside the lab scope.
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries    — restrict to known resource groups
#   AIUC-1-18  Input Validation    — reject malformed inputs early
#   AIUC-1-11  Human Oversight     — invalid inputs are logged for review
# ---------------------------------------------------------------------------

from __future__ import annotations

from typing import Optional

from .config import get_settings

# ---- SOC 2 CC Categories -------------------------------------------------

# The nine SOC 2 Common Criteria categories.  Functions that accept a
# cc_category parameter must validate against this set.
VALID_CC_CATEGORIES = {
    "CC1",  # Control Environment
    "CC2",  # Communication and Information
    "CC3",  # Risk Assessment
    "CC4",  # Monitoring Activities
    "CC5",  # Control Activities
    "CC6",  # Logical and Physical Access Controls
    "CC7",  # System Operations
    "CC8",  # Change Management
    "CC9",  # Risk Mitigation
}

# ---- CC-to-Azure-Resource Mapping -----------------------------------------

# Maps each CC category to the Azure resource types and checks relevant
# to that criteria.  Used by scan_cc_criteria and gap_analyzer to know
# which Azure APIs to call.
CC_RESOURCE_MAP: dict[str, dict] = {
    "CC1": {
        "description": "Control Environment",
        "checks": ["policy_assignments", "management_groups", "blueprints"],
    },
    "CC2": {
        "description": "Communication and Information",
        "checks": ["activity_log_alerts", "action_groups", "diagnostic_settings"],
    },
    "CC3": {
        "description": "Risk Assessment",
        "checks": ["security_assessments", "advisor_recommendations"],
    },
    "CC4": {
        "description": "Monitoring Activities",
        "checks": ["monitor_alerts", "log_analytics_workspaces", "app_insights"],
    },
    "CC5": {
        "description": "Control Activities — Storage & Encryption",
        "checks": ["storage_accounts", "encryption_at_rest", "key_vaults"],
    },
    "CC6": {
        "description": "Logical and Physical Access Controls",
        "checks": ["nsg_rules", "rbac_assignments", "entra_id_users", "mfa_status"],
    },
    "CC7": {
        "description": "System Operations — SQL & Compute",
        "checks": ["sql_auditing", "sql_tde", "vm_extensions", "backup_policies"],
    },
    "CC8": {
        "description": "Change Management",
        "checks": ["policy_compliance", "deployment_history", "terraform_state"],
    },
    "CC9": {
        "description": "Risk Mitigation",
        "checks": ["defender_score", "security_contacts", "incident_response"],
    },
}


def validate_cc_category(cc_category: str) -> Optional[str]:
    """Validate that *cc_category* is a recognised SOC 2 CC code.

    Args:
        cc_category: The CC category string to validate (e.g. "CC6").

    Returns:
        None if valid; an error message string if invalid.
    """
    normalised = cc_category.strip().upper()
    if normalised not in VALID_CC_CATEGORIES:
        return (
            f"Invalid CC category '{cc_category}'. "
            f"Must be one of: {sorted(VALID_CC_CATEGORIES)}"
        )
    return None


def validate_resource_group(resource_group: str) -> Optional[str]:
    """Validate that *resource_group* is within the lab's allowed scope.

    This is a critical security control — it prevents agents from being
    tricked (via prompt injection) into querying or modifying resources
    outside the three lab resource groups.

    Args:
        resource_group: The resource group name to validate.

    Returns:
        None if valid; an error message string if invalid.
    """
    settings = get_settings()
    allowed = settings.allowed_resource_groups

    if resource_group.strip() not in allowed:
        return (
            f"Resource group '{resource_group}' is outside lab scope. "
            f"Allowed: {allowed}. "
            f"AIUC-1-09 (Scope Boundaries) violation."
        )
    return None


def validate_required_fields(
    body: dict,
    required: list[str],
) -> Optional[str]:
    """Check that all *required* keys are present and non-empty in *body*.

    Args:
        body: The parsed JSON request body.
        required: List of required field names.

    Returns:
        None if all fields present; an error message if any are missing.
    """
    missing = [f for f in required if not body.get(f)]
    if missing:
        return f"Missing required fields: {missing}"
    return None
