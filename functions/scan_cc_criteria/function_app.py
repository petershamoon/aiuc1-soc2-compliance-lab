# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — scan_cc_criteria
# ---------------------------------------------------------------------------
# Data Provider Function (2 of 6)
#
# Purpose:
#   Returns raw Azure resource state for a given SOC 2 CC category.
#   This is the primary data-gathering function that agents call to
#   understand the current infrastructure posture.
#
# How it works:
#   1. Validates the CC category (AIUC-1-18)
#   2. Looks up which Azure resource types map to that CC category
#   3. Queries the Azure Management APIs for each resource type
#   4. Returns raw state data — no compliance judgment
#
# Design principle:
#   "Tools provide data, agents provide judgment."
#   This function is a pure data retriever.  It never says "compliant"
#   or "non-compliant" — that's the agent's job.
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — queries only allowed resource groups
#   AIUC-1-17  Data Minimization — returns only compliance-relevant fields
#   AIUC-1-18  Input Validation  — validates CC category
#   AIUC-1-19  Output Filtering  — sanitises all output
#   AIUC-1-22  Logging           — logs every invocation
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
from shared.validators import validate_cc_category, CC_RESOURCE_MAP

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.scan_cc_criteria")


# ---- Per-CC Scanner Functions ---------------------------------------------
# Each scanner returns a list of resource state dictionaries.  We extract
# only the fields that are relevant to compliance assessment (data
# minimization per AIUC-1-17).

def _scan_cc5(settings) -> list[dict]:
    """CC5 — Control Activities: storage accounts, encryption, key vaults."""
    resources = []
    storage_client = get_mgmt_client("storage")
    for rg in settings.allowed_resource_groups:
        try:
            for acct in storage_client.storage_accounts.list_by_resource_group(rg):
                resources.append({
                    "type": "storage_account",
                    "name": acct.name,
                    "resource_group": rg,
                    "location": acct.location,
                    "sku": acct.sku.name if acct.sku else None,
                    "kind": acct.kind,
                    "allow_blob_public_access": acct.allow_blob_public_access,
                    "enable_https_traffic_only": acct.enable_https_traffic_only,
                    "minimum_tls_version": acct.minimum_tls_version,
                    "encryption_key_source": (
                        acct.encryption.key_source if acct.encryption else None
                    ),
                    "infrastructure_encryption": (
                        acct.encryption.require_infrastructure_encryption
                        if acct.encryption else None
                    ),
                    "tags": dict(acct.tags) if acct.tags else {},
                })
        except Exception as e:
            logger.warning("Error scanning storage in %s: %s", rg, e)
    return resources


def _scan_cc6(settings) -> list[dict]:
    """CC6 — Logical Access Controls: NSG rules, RBAC assignments."""
    resources = []
    network_client = get_mgmt_client("network")
    for rg in settings.allowed_resource_groups:
        try:
            for nsg in network_client.network_security_groups.list(rg):
                rules = []
                for rule in (nsg.security_rules or []):
                    rules.append({
                        "name": rule.name,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "priority": rule.priority,
                    })
                resources.append({
                    "type": "network_security_group",
                    "name": nsg.name,
                    "resource_group": rg,
                    "location": nsg.location,
                    "rules": rules,
                    "tags": dict(nsg.tags) if nsg.tags else {},
                })
        except Exception as e:
            logger.warning("Error scanning NSGs in %s: %s", rg, e)
    return resources


def _scan_cc7(settings) -> list[dict]:
    """CC7 — System Operations: SQL servers, auditing, databases."""
    resources = []
    sql_client = get_mgmt_client("sql")
    for rg in settings.allowed_resource_groups:
        try:
            for server in sql_client.servers.list_by_resource_group(rg):
                server_info = {
                    "type": "sql_server",
                    "name": server.name,
                    "resource_group": rg,
                    "location": server.location,
                    "version": server.version,
                    "state": server.state,
                    "public_network_access": server.public_network_access,
                    "minimal_tls_version": server.minimal_tls_version,
                    "auditing_enabled": False,
                    "databases": [],
                    "tags": dict(server.tags) if server.tags else {},
                }

                # Check auditing
                try:
                    audit = sql_client.server_blob_auditing_policies.get(
                        rg, server.name
                    )
                    server_info["auditing_enabled"] = (audit.state == "Enabled")
                    server_info["auditing_state"] = audit.state
                except Exception:
                    server_info["auditing_state"] = "unknown"

                # List databases
                try:
                    for db in sql_client.databases.list_by_server(rg, server.name):
                        if db.name != "master":  # Skip system DB
                            server_info["databases"].append({
                                "name": db.name,
                                "sku": db.sku.name if db.sku else None,
                                "status": db.status,
                                "max_size_bytes": db.max_size_bytes,
                            })
                except Exception:
                    pass

                resources.append(server_info)
        except Exception as e:
            logger.warning("Error scanning SQL in %s: %s", rg, e)
    return resources


def _scan_generic(settings, cc_category: str) -> list[dict]:
    """Generic scanner for CC categories without specific implementations.

    Returns metadata about what checks would be performed, allowing the
    agent to understand the coverage gap and plan accordingly.
    """
    checks = CC_RESOURCE_MAP.get(cc_category, {}).get("checks", [])
    return [{
        "type": "scan_metadata",
        "cc_category": cc_category,
        "description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "planned_checks": checks,
        "status": "not_yet_implemented",
        "note": (
            "Scanner for this CC category is planned but not yet implemented. "
            "The agent should note this as a coverage gap in the assessment."
        ),
    }]


# Map CC categories to scanner functions
_SCANNERS = {
    "CC5": _scan_cc5,
    "CC6": _scan_cc6,
    "CC7": _scan_cc7,
}


@app.route(route="scan_cc_criteria", methods=["POST"])
@log_function_call("scan_cc_criteria", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Scan Azure resources relevant to a SOC 2 CC category.

    Request body (JSON):
        {
            "cc_category": "CC6"  // required — SOC 2 CC code (CC1–CC9)
        }

    Response:
        Standard envelope with resource state in data.resources[].
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "scan_cc_criteria",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    cc_category = body.get("cc_category", "").strip().upper()

    # ---- Input validation (AIUC-1-18) ------------------------------------
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response(
            "scan_cc_criteria", cc_error, error_code="INVALID_CC_CATEGORY", status_code=400
        )

    # ---- Scan resources --------------------------------------------------
    settings = get_settings()
    scanner = _SCANNERS.get(cc_category, lambda s: _scan_generic(s, cc_category))
    resources = scanner(settings)

    result = {
        "cc_category": cc_category,
        "cc_description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "resource_count": len(resources),
        "resources": resources,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": settings.allowed_resource_groups,
    }

    return build_success_response(
        "scan_cc_criteria",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"],
    )
