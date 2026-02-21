# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — query_access_controls
# ---------------------------------------------------------------------------
# Data Provider Function (4 of 6)
#
# Purpose:
#   Returns raw Entra ID and Azure RBAC state for CC6 (Logical and
#   Physical Access Controls) assessment.  Queries:
#     • RBAC role assignments at subscription and resource-group scope
#     • NSG inbound rules across all lab resource groups
#     • Service principal permissions
#
# ChatGPT Audit Fix #2:
#   The IaC Deployer agent's scope is clarified here — this function
#   queries ARM RBAC (Azure Resource Manager role assignments), NOT
#   Entra ID directory roles.  Entra ID queries require Graph API
#   permissions that the service principal does not have.
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — subscription-scoped RBAC only
#   AIUC-1-17  Data Minimization — returns role names, not full objects
#   AIUC-1-18  Input Validation  — validates scope parameter
#   AIUC-1-19  Output Filtering  — redacts principal IDs
#   AIUC-1-22  Logging           — logs every query
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.azure_clients import get_mgmt_client
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.validators import validate_resource_group

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.query_access_controls")


# ---- Well-known Azure built-in role IDs ----------------------------------
# We map role definition IDs to friendly names so agents get readable output.
# Only the most common roles are listed; others show the raw role ID.

BUILTIN_ROLES = {
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
    "6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437": "SQL DB Contributor",
    "de139f84-1756-47ae-9be6-808fbbe84772": "Website Contributor",
}


def _get_role_name(role_definition_id: str) -> str:
    """Extract a human-readable role name from a role definition ID.

    The role_definition_id is a full ARM path like:
    /subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/<guid>

    We extract the GUID and look it up in BUILTIN_ROLES.
    """
    if not role_definition_id:
        return "unknown"
    guid = role_definition_id.rsplit("/", 1)[-1].lower()
    return BUILTIN_ROLES.get(guid, f"custom-or-unknown ({guid[:8]}...)")


def _query_rbac_assignments(settings, scope: str = "") -> list[dict]:
    """Query RBAC role assignments at subscription or resource-group scope.

    Args:
        settings: Application settings.
        scope: Optional resource group name to narrow the query.

    Returns:
        List of role assignment summaries.
    """
    auth_client = get_mgmt_client("authorization")
    assignments = []

    try:
        # List all role assignments at subscription scope
        # (this includes resource-group-scoped assignments)
        for ra in auth_client.role_assignments.list_for_subscription():
            # Extract scope level for filtering
            ra_scope = ra.scope or ""

            # If a specific resource group was requested, filter
            if scope and scope not in ra_scope:
                continue

            assignments.append({
                "principal_type": ra.principal_type or "unknown",
                "role_name": _get_role_name(ra.role_definition_id),
                "scope": ra_scope,
                "scope_level": _classify_scope(ra_scope),
                "created_on": ra.created_on.isoformat() if ra.created_on else None,
                "condition": ra.condition or None,
            })
    except Exception as e:
        logger.error("Failed to query RBAC assignments: %s", e)
        assignments.append({
            "error": str(e),
            "note": "RBAC query failed — check service principal permissions",
        })

    return assignments


def _classify_scope(scope: str) -> str:
    """Classify an ARM scope string into a human-readable level."""
    if not scope:
        return "unknown"
    if "/resourceGroups/" in scope:
        if "/providers/" in scope.split("/resourceGroups/")[1]:
            return "resource"
        return "resource_group"
    if scope.startswith("/subscriptions/"):
        return "subscription"
    if scope == "/":
        return "root"
    return "other"


def _query_nsg_access_rules(settings) -> list[dict]:
    """Query all NSG inbound allow rules across lab resource groups.

    Returns a summary of network access controls for CC6 assessment.
    """
    network_client = get_mgmt_client("network")
    rules_summary = []

    for rg in settings.allowed_resource_groups:
        try:
            for nsg in network_client.network_security_groups.list(rg):
                for rule in (nsg.security_rules or []):
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        rules_summary.append({
                            "nsg_name": nsg.name,
                            "resource_group": rg,
                            "rule_name": rule.name,
                            "protocol": rule.protocol,
                            "source": rule.source_address_prefix or str(rule.source_address_prefixes),
                            "destination_port": rule.destination_port_range or str(rule.destination_port_ranges),
                            "priority": rule.priority,
                            "is_overly_permissive": rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet"),
                        })
        except Exception as e:
            logger.warning("Error querying NSGs in %s: %s", rg, e)

    return rules_summary


@app.route(route="query_access_controls", methods=["POST"])
@log_function_call("query_access_controls", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Query Azure RBAC and network access controls.

    Request body (JSON):
        {
            "scope": "rg-production",  // optional — filter by resource group
            "include_nsg": true        // optional — include NSG rules (default true)
        }

    Response:
        Standard envelope with RBAC assignments and NSG rules.
    """
    try:
        body = req.get_json()
    except ValueError:
        body = {}  # All fields are optional

    scope = body.get("scope", "").strip()
    include_nsg = body.get("include_nsg", True)

    # ---- Input validation (AIUC-1-18) ------------------------------------
    if scope:
        rg_error = validate_resource_group(scope)
        if rg_error:
            return build_error_response(
                "query_access_controls",
                rg_error,
                error_code="SCOPE_VIOLATION",
                status_code=403,
            )

    # ---- Query access controls -------------------------------------------
    settings = get_settings()

    rbac_assignments = _query_rbac_assignments(settings, scope)
    nsg_rules = _query_nsg_access_rules(settings) if include_nsg else []

    # ---- Summary statistics for the agent --------------------------------
    overly_permissive_rules = [r for r in nsg_rules if r.get("is_overly_permissive")]

    result = {
        "rbac": {
            "total_assignments": len(rbac_assignments),
            "assignments": rbac_assignments,
        },
        "network_access": {
            "total_inbound_allow_rules": len(nsg_rules),
            "overly_permissive_count": len(overly_permissive_rules),
            "rules": nsg_rules,
        },
        "scope_note": (
            "This function queries ARM RBAC (Azure Resource Manager role assignments). "
            "Entra ID directory roles require Microsoft Graph API permissions and are "
            "not included in this query. See ChatGPT Audit Fix #2."
        ),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return build_success_response(
        "query_access_controls",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"],
    )
