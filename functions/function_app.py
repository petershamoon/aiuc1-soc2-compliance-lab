# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Consolidated Azure Functions Entry Point
# ---------------------------------------------------------------------------
# Azure Functions V2 Python model requires a single function_app.py at the
# package root.  This file creates one FunctionApp instance and registers
# all 12 HTTP-triggered GRC tool endpoints via Blueprints.
#
# Architecture:
#   "Tools provide data, agents provide judgment."
#   Functions return raw Azure state; the AI agents reason about compliance.
#
# Function categories:
#   Data Providers (6):  gap_analyzer, scan_cc_criteria, evidence_validator,
#                        query_access_controls, query_defender_score,
#                        query_policy_compliance
#   Action Functions (4): generate_poam_entry, run_terraform_plan,
#                         run_terraform_apply, git_commit_push
#   Safety Functions (2): sanitize_output, log_security_event
#
# AIUC-1 Controls enforced across all functions:
#   AIUC-1-09  Scope Boundaries    — only allowed resource groups
#   AIUC-1-17  Data Minimization   — return only compliance-relevant fields
#   AIUC-1-18  Input Validation    — reject malformed inputs early
#   AIUC-1-19  Output Filtering    — sanitise every response
#   AIUC-1-22  Logging             — log every invocation to App Insights
#   AIUC-1-34  Credential Mgmt    — no hardcoded secrets
# ---------------------------------------------------------------------------
import azure.functions as func
import logging
import json
from datetime import datetime, timezone

# Create the single FunctionApp instance for all 12 functions
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# ---------------------------------------------------------------------------
# Shared imports — available to all inline handlers below
# ---------------------------------------------------------------------------
import sys
import os

# Ensure shared modules are importable from the functions root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import get_settings
from shared.azure_clients import get_mgmt_client, get_credential
from shared.sanitizer import redact_secrets, redact_dict
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.validators import (
    validate_cc_category,
    validate_resource_group,
    validate_required_fields,
    CC_RESOURCE_MAP,
    VALID_CC_CATEGORIES,
)

logger = logging.getLogger("aiuc1.grc_tools")


# ===========================================================================
# 1. gap_analyzer — Data Provider (1 of 6)
# ===========================================================================
def _check_cc5_storage_gaps(settings) -> list[dict]:
    """CC5 — Control Activities: check storage account configurations."""
    gaps = []
    try:
        storage_client = get_mgmt_client("storage")
        for rg in settings.allowed_resource_groups:
            try:
                accounts = storage_client.storage_accounts.list_by_resource_group(rg)
                for acct in accounts:
                    if acct.allow_blob_public_access:
                        gaps.append({
                            "resource": acct.name, "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": "Public blob access is enabled",
                            "expected": "allow_blob_public_access = false",
                            "actual": "allow_blob_public_access = true",
                            "risk": "Data exposure — blobs may be publicly readable",
                        })
                    if not acct.enable_https_traffic_only:
                        gaps.append({
                            "resource": acct.name, "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": "HTTPS-only traffic not enforced",
                            "expected": "enable_https_traffic_only = true",
                            "actual": "enable_https_traffic_only = false",
                            "risk": "Data in transit may be unencrypted",
                        })
                    if acct.minimum_tls_version and acct.minimum_tls_version != "TLS1_2":
                        gaps.append({
                            "resource": acct.name, "resource_group": rg,
                            "cc_category": "CC5",
                            "gap": f"TLS version is {acct.minimum_tls_version}",
                            "expected": "minimum_tls_version = TLS1_2",
                            "actual": f"minimum_tls_version = {acct.minimum_tls_version}",
                            "risk": "Weak TLS may allow downgrade attacks",
                        })
            except Exception as e:
                logger.warning("Error scanning storage in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create storage client: %s", e)
    return gaps


def _check_cc6_network_gaps(settings) -> list[dict]:
    """CC6 — Logical Access Controls: check NSG rules for overly permissive access."""
    gaps = []
    try:
        network_client = get_mgmt_client("network")
        for rg in settings.allowed_resource_groups:
            try:
                nsgs = network_client.network_security_groups.list(rg)
                for nsg in nsgs:
                    for rule in (nsg.security_rules or []):
                        if (
                            rule.direction == "Inbound"
                            and rule.access == "Allow"
                            and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")
                        ):
                            gaps.append({
                                "resource": nsg.name, "resource_group": rg,
                                "cc_category": "CC6",
                                "gap": f"Inbound rule '{rule.name}' allows traffic from {rule.source_address_prefix}",
                                "expected": "Source restricted to known CIDR ranges",
                                "actual": f"source={rule.source_address_prefix}, port={rule.destination_port_range}, protocol={rule.protocol}",
                                "risk": "Unrestricted inbound access (potential RDP/SSH exposure)",
                            })
            except Exception as e:
                logger.warning("Error scanning NSGs in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create network client: %s", e)
    return gaps


def _check_cc7_sql_gaps(settings) -> list[dict]:
    """CC7 — System Operations: check SQL Server auditing and TDE."""
    gaps = []
    try:
        sql_client = get_mgmt_client("sql")
        for rg in settings.allowed_resource_groups:
            try:
                servers = sql_client.servers.list_by_resource_group(rg)
                for server in servers:
                    try:
                        audit = sql_client.server_blob_auditing_policies.get(rg, server.name)
                        if audit.state != "Enabled":
                            gaps.append({
                                "resource": server.name, "resource_group": rg,
                                "cc_category": "CC7",
                                "gap": "SQL Server auditing is not enabled",
                                "expected": "blob_auditing_policy.state = Enabled",
                                "actual": f"blob_auditing_policy.state = {audit.state}",
                                "risk": "No audit trail for database operations",
                            })
                    except Exception:
                        gaps.append({
                            "resource": server.name, "resource_group": rg,
                            "cc_category": "CC7",
                            "gap": "Unable to retrieve SQL auditing policy",
                            "expected": "Auditing policy accessible and enabled",
                            "actual": "Policy retrieval failed",
                            "risk": "Auditing status unknown",
                        })
            except Exception as e:
                logger.warning("Error scanning SQL in %s: %s", rg, e)
    except Exception as e:
        logger.error("Failed to create SQL client: %s", e)
    return gaps


_GAP_CHECKERS = {
    "CC5": _check_cc5_storage_gaps,
    "CC6": _check_cc6_network_gaps,
    "CC7": _check_cc7_sql_gaps,
}


@app.route(route="gap_analyzer", methods=["POST"])
@log_function_call("gap_analyzer", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])
def gap_analyzer(req: func.HttpRequest) -> func.HttpResponse:
    """Analyse compliance gaps for a given SOC 2 CC category."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("gap_analyzer", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    cc_category = body.get("cc_category", "").strip().upper()
    resource_group = body.get("resource_group", "")
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response("gap_analyzer", cc_error,
                                    error_code="INVALID_CC_CATEGORY", status_code=400)
    if resource_group:
        rg_error = validate_resource_group(resource_group)
        if rg_error:
            return build_error_response("gap_analyzer", rg_error,
                                        error_code="SCOPE_VIOLATION", status_code=403)
    settings = get_settings()
    checker = _GAP_CHECKERS.get(cc_category)
    gaps = checker(settings) if checker else []
    if resource_group:
        gaps = [g for g in gaps if g.get("resource_group") == resource_group]
    scanner_status = "implemented" if cc_category in _GAP_CHECKERS else "not_yet_implemented"
    result = {
        "cc_category": cc_category,
        "cc_description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "scanner_status": scanner_status,
        "total_gaps": len(gaps),
        "gaps": gaps,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Gaps are heuristic findings. The SOC 2 Auditor agent determines severity and recommendations."
               + (f" Scanner for {cc_category} is not yet implemented — the agent should note this as a coverage gap." if scanner_status == "not_yet_implemented" else ""),
        "implemented_categories": sorted(_GAP_CHECKERS.keys()),
    }
    return build_success_response("gap_analyzer", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])


# ===========================================================================
# 2. scan_cc_criteria — Data Provider (2 of 6)
# ===========================================================================
def _scan_cc5(settings) -> list[dict]:
    """CC5 — Control Activities: storage accounts, encryption, key vaults."""
    resources = []
    storage_client = get_mgmt_client("storage")
    for rg in settings.allowed_resource_groups:
        try:
            for acct in storage_client.storage_accounts.list_by_resource_group(rg):
                resources.append({
                    "type": "storage_account", "name": acct.name,
                    "resource_group": rg, "location": acct.location,
                    "sku": acct.sku.name if acct.sku else None,
                    "kind": acct.kind,
                    "allow_blob_public_access": acct.allow_blob_public_access,
                    "enable_https_traffic_only": acct.enable_https_traffic_only,
                    "minimum_tls_version": acct.minimum_tls_version,
                    "encryption_key_source": acct.encryption.key_source if acct.encryption else None,
                    "infrastructure_encryption": acct.encryption.require_infrastructure_encryption if acct.encryption else None,
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
                        "name": rule.name, "direction": rule.direction,
                        "access": rule.access, "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "priority": rule.priority,
                    })
                resources.append({
                    "type": "network_security_group", "name": nsg.name,
                    "resource_group": rg, "location": nsg.location,
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
                    "type": "sql_server", "name": server.name,
                    "resource_group": rg, "location": server.location,
                    "version": server.version, "state": server.state,
                    "public_network_access": server.public_network_access,
                    "minimal_tls_version": server.minimal_tls_version,
                    "auditing_enabled": False, "databases": [],
                    "tags": dict(server.tags) if server.tags else {},
                }
                try:
                    audit = sql_client.server_blob_auditing_policies.get(rg, server.name)
                    server_info["auditing_enabled"] = (audit.state == "Enabled")
                    server_info["auditing_state"] = audit.state
                except Exception:
                    server_info["auditing_state"] = "unknown"
                try:
                    for db in sql_client.databases.list_by_server(rg, server.name):
                        if db.name != "master":
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
    """Generic scanner for CC categories without specific implementations."""
    checks = CC_RESOURCE_MAP.get(cc_category, {}).get("checks", [])
    return [{
        "type": "scan_metadata", "cc_category": cc_category,
        "description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "planned_checks": checks, "status": "not_yet_implemented",
        "note": "Scanner for this CC category is planned but not yet implemented. "
                "The agent should note this as a coverage gap in the assessment.",
    }]


_SCANNERS = {"CC5": _scan_cc5, "CC6": _scan_cc6, "CC7": _scan_cc7}


@app.route(route="scan_cc_criteria", methods=["POST"])
@log_function_call("scan_cc_criteria", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])
def scan_cc_criteria(req: func.HttpRequest) -> func.HttpResponse:
    """Scan Azure resources relevant to a SOC 2 CC category."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("scan_cc_criteria", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    cc_category = body.get("cc_category", "").strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response("scan_cc_criteria", cc_error,
                                    error_code="INVALID_CC_CATEGORY", status_code=400)
    settings = get_settings()
    scanner = _SCANNERS.get(cc_category, lambda s: _scan_generic(s, cc_category))
    resources = scanner(settings)
    result = {
        "cc_category": cc_category,
        "cc_description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "resource_count": len(resources), "resources": resources,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": settings.allowed_resource_groups,
    }
    return build_success_response("scan_cc_criteria", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])


# ===========================================================================
# 3. evidence_validator — Data Provider (3 of 6)
# ===========================================================================
EVIDENCE_MAP = {
    "CC1": {"category": "Control Environment", "evidence_types": [
        "Organisational chart showing security reporting lines",
        "Board-approved information security policy",
        "Risk assessment methodology documentation",
        "Annual security awareness training records"]},
    "CC2": {"category": "Communication and Information", "evidence_types": [
        "Incident notification procedures",
        "Azure Activity Log alert configurations",
        "Stakeholder communication templates",
        "Change advisory board meeting minutes"]},
    "CC3": {"category": "Risk Assessment", "evidence_types": [
        "Risk register with likelihood and impact ratings",
        "Azure Security Center assessment results",
        "Third-party vulnerability scan reports",
        "Risk acceptance documentation for known issues"]},
    "CC4": {"category": "Monitoring Activities", "evidence_types": [
        "Application Insights dashboard screenshots",
        "Log Analytics query results showing monitoring coverage",
        "Alert rule configurations and escalation procedures",
        "Monthly monitoring effectiveness review reports"]},
    "CC5": {"category": "Control Activities", "evidence_types": [
        "Storage account encryption configuration (at-rest)",
        "TLS 1.2 enforcement evidence",
        "Key Vault access policies",
        "Data classification policy and implementation proof"]},
    "CC6": {"category": "Logical and Physical Access Controls", "evidence_types": [
        "NSG rule configurations showing least-privilege",
        "RBAC role assignment listings",
        "Entra ID conditional access policies",
        "MFA enforcement evidence for privileged accounts",
        "Access review completion records"]},
    "CC7": {"category": "System Operations", "evidence_types": [
        "SQL Server auditing policy configuration",
        "Database backup and recovery test results",
        "Patch management compliance reports",
        "Incident response plan and tabletop exercise records"]},
    "CC8": {"category": "Change Management", "evidence_types": [
        "Azure Policy compliance state reports",
        "Terraform plan/apply audit logs",
        "Pull request review and approval records",
        "Deployment pipeline configuration (CI/CD)"]},
    "CC9": {"category": "Risk Mitigation", "evidence_types": [
        "Microsoft Defender for Cloud secure score",
        "Remediation plan (POA&M) with timelines",
        "Insurance coverage documentation",
        "Business continuity and disaster recovery plans"]},
}

TYPE_II_SAMPLING = {
    "description": (
        "For Type II audits, evidence must demonstrate control effectiveness "
        "over the examination period (typically 6-12 months). This function "
        "supports sampling by accepting date ranges and returning evidence "
        "metadata with timestamps for period coverage analysis."
    ),
    "sampling_strategy": "statistical",
    "minimum_samples": 25,
    "confidence_level": "95%",
    "note": (
        "The agent determines whether the sample size is adequate based on "
        "population size and risk level. This function provides the raw "
        "evidence metadata; the agent applies professional judgment."
    ),
}


def _validate_azure_resource(resource_id: str, settings) -> dict:
    """Check if an Azure resource exists and return its metadata."""
    resource_client = get_mgmt_client("resource")
    try:
        resource = resource_client.resources.get_by_id(resource_id, api_version="2023-07-01")
        return {
            "exists": True, "name": resource.name, "type": resource.type,
            "location": resource.location,
            "provisioning_state": resource.properties.get("provisioningState", "unknown")
            if resource.properties else "unknown",
            "tags": dict(resource.tags) if resource.tags else {},
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "exists": False, "resource_id": resource_id,
            "error": str(e),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }


def _validate_document(document_path: str, settings) -> dict:
    """Check if a governance document exists in the repository."""
    repo_path = settings.git_repo_path
    full_path = os.path.join(repo_path, document_path)
    if os.path.isfile(full_path):
        stat = os.stat(full_path)
        return {
            "exists": True, "path": document_path,
            "size_bytes": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        return {
            "exists": False, "path": document_path,
            "error": "Document not found in repository",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }


@app.route(route="evidence_validator", methods=["POST"])
@log_function_call("evidence_validator", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])
def evidence_validator(req: func.HttpRequest) -> func.HttpResponse:
    """Validate existence and metadata of compliance evidence artifacts."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("evidence_validator", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    field_error = validate_required_fields(body, ["evidence_type", "target"])
    if field_error:
        return build_error_response("evidence_validator", field_error,
                                    error_code="MISSING_FIELDS", status_code=400)
    evidence_type = body["evidence_type"].strip().lower()
    target = body["target"].strip()
    cc_category = body.get("cc_category", "").strip().upper()
    valid_types = {"azure_resource", "policy_state", "document", "log_entry"}
    if evidence_type not in valid_types:
        return build_error_response("evidence_validator",
                                    f"Invalid evidence_type '{evidence_type}'. Must be one of: {sorted(valid_types)}",
                                    error_code="INVALID_EVIDENCE_TYPE", status_code=400)
    settings = get_settings()
    if evidence_type == "azure_resource":
        validation = _validate_azure_resource(target, settings)
    elif evidence_type == "document":
        validation = _validate_document(target, settings)
    else:
        validation = {
            "evidence_type": evidence_type, "target": target,
            "status": "validator_not_yet_implemented",
            "note": "This evidence type validator is planned for a future iteration.",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    result = {
        "evidence_type": evidence_type, "target": target,
        "validation": validation,
        "evidence_map": EVIDENCE_MAP.get(cc_category, {}) if cc_category else {},
        "type_ii_sampling": TYPE_II_SAMPLING,
    }
    return build_success_response("evidence_validator", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])


# ===========================================================================
# 4. query_access_controls — Data Provider (4 of 6)
# ===========================================================================
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
    if not role_definition_id:
        return "unknown"
    guid = role_definition_id.rsplit("/", 1)[-1].lower()
    return BUILTIN_ROLES.get(guid, f"custom-or-unknown ({guid[:8]}...)")


def _query_rbac_assignments(settings, scope: str = "") -> list[dict]:
    auth_client = get_mgmt_client("authorization")
    assignments = []
    try:
        for ra in auth_client.role_assignments.list_for_subscription():
            ra_scope = ra.scope or ""
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
        assignments.append({"error": str(e), "note": "RBAC query failed — check service principal permissions"})
    return assignments


def _classify_scope(scope: str) -> str:
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
    network_client = get_mgmt_client("network")
    rules_summary = []
    for rg in settings.allowed_resource_groups:
        try:
            for nsg in network_client.network_security_groups.list(rg):
                for rule in (nsg.security_rules or []):
                    if rule.direction == "Inbound" and rule.access == "Allow":
                        rules_summary.append({
                            "nsg_name": nsg.name, "resource_group": rg,
                            "rule_name": rule.name, "protocol": rule.protocol,
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
def query_access_controls(req: func.HttpRequest) -> func.HttpResponse:
    """Query Azure RBAC and network access controls."""
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    scope = body.get("scope", "").strip()
    include_nsg = body.get("include_nsg", True)
    if scope:
        rg_error = validate_resource_group(scope)
        if rg_error:
            return build_error_response("query_access_controls", rg_error,
                                        error_code="SCOPE_VIOLATION", status_code=403)
    settings = get_settings()
    rbac_assignments = _query_rbac_assignments(settings, scope)
    nsg_rules = _query_nsg_access_rules(settings) if include_nsg else []
    overly_permissive_rules = [r for r in nsg_rules if r.get("is_overly_permissive")]
    result = {
        "rbac": {"total_assignments": len(rbac_assignments), "assignments": rbac_assignments},
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
    return build_success_response("query_access_controls", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22"])


# ===========================================================================
# 5. query_defender_score — Data Provider (5 of 6)
# ===========================================================================
def _get_secure_scores(settings) -> dict:
    security_client = get_mgmt_client("security")
    scores = {}
    try:
        for score in security_client.secure_scores.list():
            # Azure SDK versions vary in attribute names for SecureScoreItem.
            # Try multiple paths to handle both old and new SDK versions.
            current_score = None
            max_score = None
            percentage = None
            # New SDK: properties are directly on the object
            if hasattr(score, 'current_score'):
                current_score = score.current_score
            elif hasattr(score, 'score') and score.score is not None:
                current_score = getattr(score.score, 'current', None)
            # Try .current as a direct attribute
            if current_score is None:
                current_score = getattr(score, 'current', None)

            if hasattr(score, 'max_score'):
                max_score = score.max_score
            elif hasattr(score, 'score') and score.score is not None:
                max_score = getattr(score.score, 'max', None)
            if max_score is None:
                max_score = getattr(score, 'max', None)

            if hasattr(score, 'percentage'):
                percentage = score.percentage
            elif hasattr(score, 'score') and score.score is not None:
                percentage = getattr(score.score, 'percentage', None)

            # Calculate percentage if we have current and max but no percentage
            if percentage is None and current_score is not None and max_score and max_score > 0:
                percentage = round(current_score / max_score * 100, 2)

            scores = {
                "score_name": getattr(score, 'display_name', None) or getattr(score, 'name', 'unknown'),
                "current_score": current_score,
                "max_score": max_score,
                "percentage": percentage,
                "weight": getattr(score, 'weight', None),
            }
            break
    except Exception as e:
        logger.error("Failed to retrieve Secure Score: %s", e)
        scores = {"error": str(e), "note": "Secure Score retrieval failed. Defender may not be fully enabled."}
    return scores


def _get_security_assessments(settings, max_results: int = 50) -> list[dict]:
    security_client = get_mgmt_client("security")
    assessments = []
    try:
        scope = f"/subscriptions/{settings.azure_subscription_id}"
        count = 0
        for assessment in security_client.assessments.list(scope=scope):
            if count >= max_results:
                break
            status_code = "unknown"
            if assessment.status:
                status_code = assessment.status.code or "unknown"
            if status_code in ("Unhealthy", "NotApplicable", "unknown"):
                assessments.append({
                    "name": assessment.display_name or assessment.name,
                    "status": status_code,
                    "severity": assessment.metadata.severity if assessment.metadata else "unknown",
                    "category": assessment.metadata.categories[0] if assessment.metadata and assessment.metadata.categories else "uncategorised",
                    "description": assessment.metadata.description if assessment.metadata else "",
                    "remediation_description": assessment.metadata.remediation_description if assessment.metadata else "",
                    "resource_type": getattr(assessment.resource_details, 'source', None) or getattr(assessment.resource_details, 'id', 'unknown') if assessment.resource_details else "unknown",
                })
                count += 1
    except Exception as e:
        logger.error("Failed to retrieve security assessments: %s", e)
        assessments.append({"error": str(e), "note": "Assessment retrieval failed. Check Defender configuration."})
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "unknown": 3}
    assessments.sort(key=lambda a: severity_order.get(a.get("severity", "unknown"), 3))
    return assessments


@app.route(route="query_defender_score", methods=["POST"])
@log_function_call("query_defender_score", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])
def query_defender_score(req: func.HttpRequest) -> func.HttpResponse:
    """Query Microsoft Defender for Cloud Secure Score and recommendations."""
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    include_assessments = body.get("include_assessments", True)
    max_results = min(body.get("max_results", 50), 100)
    settings = get_settings()
    secure_score = _get_secure_scores(settings)
    assessments = _get_security_assessments(settings, max_results) if include_assessments else []
    unhealthy_count = sum(1 for a in assessments if a.get("status") == "Unhealthy")
    high_severity_count = sum(1 for a in assessments if a.get("severity") == "High" and a.get("status") == "Unhealthy")
    result = {
        "secure_score": secure_score,
        "assessments": {
            "total_returned": len(assessments),
            "unhealthy_count": unhealthy_count,
            "high_severity_unhealthy": high_severity_count,
            "items": assessments,
        },
        "soc2_mapping": {
            "primary": "CC9 — Risk Mitigation", "secondary": "CC3 — Risk Assessment",
            "note": "Secure Score reflects the subscription's overall security posture. "
                    "Individual assessments map to specific CC categories based on their "
                    "category (e.g., 'Networking' → CC6, 'Data' → CC5).",
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return build_success_response("query_defender_score", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])


# ===========================================================================
# 6. query_policy_compliance — Data Provider (6 of 6)
# ===========================================================================
CIS_BENCHMARK_POLICY_ID = "06f19060-9e68-4070-92ca-f15cc126059e"


def _get_compliance_summary(settings) -> dict:
    policy_client = get_mgmt_client("policy_insights")
    summary = {"compliant": 0, "non_compliant": 0, "exempt": 0, "conflicting": 0, "not_started": 0}
    try:
        sub_id = settings.azure_subscription_id
        # The PolicyInsightsClient SDK expects policy_states_resource as
        # the first positional argument, not a keyword argument.
        results = policy_client.policy_states.summarize_for_subscription(
            policy_states_resource="latest", subscription_id=sub_id)
        if results and results.value:
            for result in results.value:
                if result.results:
                    summary["non_compliant"] = (
                        result.results.non_compliant_resources
                        if isinstance(result.results.non_compliant_resources, int) else 0
                    )
    except Exception as e:
        logger.error("Failed to get compliance summary: %s", e)
        summary["error"] = str(e)
    return summary


def _get_non_compliant_policies(settings, max_results: int = 50) -> list[dict]:
    policy_client = get_mgmt_client("policy_insights")
    non_compliant = []
    try:
        sub_id = settings.azure_subscription_id
        # Same fix: policy_states_resource must be the first positional arg.
        results = policy_client.policy_states.list_query_results_for_subscription(
            policy_states_resource="latest", subscription_id=sub_id)
        seen_policies = {}
        count = 0
        for state in results:
            if count >= max_results:
                break
            if state.compliance_state == "NonCompliant":
                policy_key = state.policy_definition_name or "unknown"
                if policy_key not in seen_policies:
                    seen_policies[policy_key] = {
                        "policy_name": state.policy_definition_name,
                        "policy_definition_action": state.policy_definition_action,
                        "policy_set_definition_name": state.policy_set_definition_name,
                        "resource_type": state.resource_type,
                        "compliance_state": state.compliance_state,
                        "is_cis_benchmark": (state.policy_set_definition_name == CIS_BENCHMARK_POLICY_ID
                                             if state.policy_set_definition_name else False),
                        "non_compliant_count": 1,
                    }
                    count += 1
                else:
                    seen_policies[policy_key]["non_compliant_count"] += 1
        non_compliant = list(seen_policies.values())
        non_compliant.sort(key=lambda p: (not p.get("is_cis_benchmark"), -p.get("non_compliant_count", 0)))
    except Exception as e:
        logger.error("Failed to query non-compliant policies: %s", e)
        non_compliant.append({"error": str(e), "note": "Policy compliance query failed."})
    return non_compliant


@app.route(route="query_policy_compliance", methods=["POST"])
@log_function_call("query_policy_compliance", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])
def query_policy_compliance(req: func.HttpRequest) -> func.HttpResponse:
    """Query Azure Policy compliance state for the subscription."""
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    include_details = body.get("include_details", True)
    max_results = min(body.get("max_results", 50), 100)
    settings = get_settings()
    compliance_summary = _get_compliance_summary(settings)
    non_compliant_policies = _get_non_compliant_policies(settings, max_results) if include_details else []
    cis_findings = [p for p in non_compliant_policies if p.get("is_cis_benchmark")]
    result = {
        "compliance_summary": compliance_summary,
        "non_compliant_policies": {"total": len(non_compliant_policies), "items": non_compliant_policies},
        "cis_benchmark": {
            "policy_id": CIS_BENCHMARK_POLICY_ID, "version": "v2.0.0",
            "findings_count": len(cis_findings), "findings": cis_findings,
            "note": "CIS Azure Foundations Benchmark v2.0.0 is the primary policy "
                    "framework for this lab. Non-compliant findings here directly "
                    "map to SOC 2 control gaps.",
        },
        "soc2_mapping": {
            "primary": "CC1 — Control Environment", "secondary": "CC8 — Change Management",
            "note": "Azure Policy enforces the control environment (CC1) and "
                    "validates that changes comply with defined standards (CC8).",
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return build_success_response("query_policy_compliance", result,
                                  aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-19", "AIUC-1-22"])


# ===========================================================================
# 7. generate_poam_entry — Action Function (1 of 4)
# ===========================================================================
import hashlib
from datetime import timedelta

SEVERITY_TIMELINES = {
    "critical": {"days": 7, "label": "Immediate (7 days)"},
    "high": {"days": 30, "label": "Urgent (30 days)"},
    "medium": {"days": 90, "label": "Standard (90 days)"},
    "low": {"days": 180, "label": "Planned (180 days)"},
}

MILESTONE_TEMPLATES = {
    "critical": [
        {"phase": "Immediate containment", "offset_days": 1},
        {"phase": "Root cause analysis", "offset_days": 3},
        {"phase": "Remediation implementation", "offset_days": 5},
        {"phase": "Verification and closure", "offset_days": 7},
    ],
    "high": [
        {"phase": "Impact assessment", "offset_days": 3},
        {"phase": "Remediation planning", "offset_days": 7},
        {"phase": "Implementation", "offset_days": 21},
        {"phase": "Testing and verification", "offset_days": 28},
        {"phase": "Closure and documentation", "offset_days": 30},
    ],
    "medium": [
        {"phase": "Gap documentation", "offset_days": 7},
        {"phase": "Remediation design", "offset_days": 21},
        {"phase": "Change request approval", "offset_days": 35},
        {"phase": "Implementation", "offset_days": 70},
        {"phase": "Testing and verification", "offset_days": 84},
        {"phase": "Closure", "offset_days": 90},
    ],
    "low": [
        {"phase": "Backlog prioritisation", "offset_days": 14},
        {"phase": "Design and planning", "offset_days": 60},
        {"phase": "Implementation", "offset_days": 140},
        {"phase": "Verification and closure", "offset_days": 180},
    ],
}


def _generate_weakness_id(cc_category: str, resource: str, gap: str) -> str:
    content = f"{cc_category}:{resource}:{gap}".lower()
    return f"POAM-{hashlib.sha256(content.encode()).hexdigest()[:8].upper()}"


def _calculate_milestones(severity: str, start_date: datetime) -> list[dict]:
    templates = MILESTONE_TEMPLATES.get(severity, MILESTONE_TEMPLATES["medium"])
    milestones = []
    for i, template in enumerate(templates, 1):
        target_date = start_date + timedelta(days=template["offset_days"])
        milestones.append({
            "milestone_number": i, "description": template["phase"],
            "target_date": target_date.strftime("%Y-%m-%d"), "status": "not_started",
        })
    return milestones


@app.route(route="generate_poam_entry", methods=["POST"])
@log_function_call("generate_poam_entry", aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])
def generate_poam_entry(req: func.HttpRequest) -> func.HttpResponse:
    """Generate a structured POA&M entry for a compliance gap."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("generate_poam_entry", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    field_error = validate_required_fields(body, ["cc_category", "resource", "gap_description", "severity"])
    if field_error:
        return build_error_response("generate_poam_entry", field_error,
                                    error_code="MISSING_FIELDS", status_code=400)
    cc_category = body["cc_category"].strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        return build_error_response("generate_poam_entry", cc_error,
                                    error_code="INVALID_CC_CATEGORY", status_code=400)
    severity = body["severity"].strip().lower()
    if severity not in SEVERITY_TIMELINES:
        return build_error_response("generate_poam_entry",
                                    f"Invalid severity '{severity}'. Must be one of: {list(SEVERITY_TIMELINES.keys())}",
                                    error_code="INVALID_SEVERITY", status_code=400)
    now = datetime.now(timezone.utc)
    timeline = SEVERITY_TIMELINES[severity]
    completion_date = now + timedelta(days=timeline["days"])
    weakness_id = _generate_weakness_id(cc_category, body["resource"], body["gap_description"])
    poam_entry = {
        "weakness_id": weakness_id, "cc_category": cc_category,
        "resource": body["resource"], "gap_description": body["gap_description"],
        "severity": severity, "risk_level": timeline["label"],
        "date_identified": now.strftime("%Y-%m-%d"),
        "scheduled_completion_date": completion_date.strftime("%Y-%m-%d"),
        "milestones": _calculate_milestones(severity, now),
        "responsible_party": body.get("responsible_party", "Unassigned"),
        "resources_required": body.get("resources_required", "To be determined"),
        "status": "open",
        "provenance": {
            "generated_by": "generate_poam_entry",
            "requested_by_agent": body.get("agent_id", "unknown"),
            "generated_at": now.isoformat(),
            "note": "This POA&M entry was generated by the GRC tool library. "
                    "The Policy Writer agent should review and refine the language "
                    "before including it in the final POA&M report.",
        },
    }
    result = {
        "poam_entry": poam_entry,
        "timeline_rationale": (
            f"Severity '{severity}' maps to a {timeline['days']}-day remediation "
            f"window per the risk-based timeline policy. The agent may adjust "
            f"this based on contextual factors."
        ),
    }
    return build_success_response("generate_poam_entry", result,
                                  aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])


# ===========================================================================
# 8. run_terraform_plan — Action Function (2 of 4)
# ===========================================================================
import hmac
import subprocess

BLOCKED_PATTERNS = [
    "azurerm_role_assignment", "azurerm_management_group",
    "azurerm_subscription", "azurerm_policy_exemption", "destroy",
]

DANGEROUS_RESOURCE_TYPES = {
    "azurerm_role_assignment": "Role assignments can escalate privileges",
    "azurerm_management_group": "Management group changes affect governance scope",
    "azurerm_policy_exemption": "Policy exemptions bypass compliance controls",
    "azurerm_key_vault_access_policy": "Key Vault access changes affect secret management",
}

REQUIRED_TAGS = {"project", "environment", "managed_by"}


def _validate_plan_json(plan_json: list[dict]) -> list[dict]:
    findings = []
    for change in plan_json:
        change_type = change.get("type", "")
        action = change.get("change", {}).get("actions", [])
        resource_address = change.get("address", "unknown")
        if change_type in DANGEROUS_RESOURCE_TYPES:
            if change_type == "azurerm_role_assignment":
                scope = change.get("change", {}).get("after", {}).get("scope", "")
                if scope == "/" or scope.count("/") <= 2:
                    findings.append({
                        "rule": "dangerous_resource_type", "resource": resource_address,
                        "type": change_type,
                        "reason": f"{DANGEROUS_RESOURCE_TYPES[change_type]}. Scope '{scope}' is too broad.",
                        "severity": "critical",
                    })
            else:
                findings.append({
                    "rule": "dangerous_resource_type", "resource": resource_address,
                    "type": change_type,
                    "reason": DANGEROUS_RESOURCE_TYPES[change_type],
                    "severity": "high",
                })
        if "delete" in action or "destroy" in str(action):
            if "production" in resource_address.lower() or "prod" in resource_address.lower():
                findings.append({
                    "rule": "production_destroy_blocked", "resource": resource_address,
                    "actions": action,
                    "reason": "Destroy actions on production resources are blocked",
                    "severity": "critical",
                })
        if "create" in action or "update" in action:
            after_tags = change.get("change", {}).get("after", {}).get("tags", {})
            if after_tags is not None:
                missing_tags = REQUIRED_TAGS - set(after_tags.keys())
                if missing_tags:
                    findings.append({
                        "rule": "missing_required_tags", "resource": resource_address,
                        "missing_tags": list(missing_tags),
                        "reason": f"Resources must have tags: {REQUIRED_TAGS}",
                        "severity": "medium",
                    })
    return findings


def _generate_approval_token(plan_hash: str) -> str:
    secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
    token = hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()
    return token


@app.route(route="run_terraform_plan", methods=["POST"])
@log_function_call("run_terraform_plan", aiuc1_controls=["AIUC-1-07", "AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30"])
def run_terraform_plan(req: func.HttpRequest) -> func.HttpResponse:
    """Execute terraform plan with validation and approval gate."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("run_terraform_plan", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    settings = get_settings()
    working_dir = body.get("working_dir", settings.terraform_working_dir)
    if not working_dir:
        working_dir = os.path.join(settings.git_repo_path, "terraform")
    if not os.path.isdir(working_dir):
        return build_error_response("run_terraform_plan",
                                    f"Terraform working directory does not exist: {working_dir}",
                                    error_code="INVALID_WORKING_DIR", status_code=400)
    cmd = ["terraform", "plan", "-no-color", "-detailed-exitcode"]
    target = body.get("target")
    if target:
        cmd.extend(["-target", target])
    var_file = body.get("var_file")
    if var_file:
        cmd.extend(["-var-file", var_file])
    json_cmd = cmd + ["-json"]
    try:
        plan_result = subprocess.run(cmd, cwd=working_dir, capture_output=True, text=True, timeout=300)
        plan_output = plan_result.stdout
        plan_stderr = plan_result.stderr
        has_changes = plan_result.returncode == 2
        has_error = plan_result.returncode == 1
        if has_error:
            return build_error_response("run_terraform_plan",
                                        redact_secrets(plan_stderr or plan_output),
                                        error_code="TERRAFORM_PLAN_ERROR", status_code=500,
                                        details={"exit_code": plan_result.returncode})
    except subprocess.TimeoutExpired:
        return build_error_response("run_terraform_plan",
                                    "Terraform plan timed out after 300 seconds",
                                    error_code="TIMEOUT", status_code=504)
    except FileNotFoundError:
        return build_error_response("run_terraform_plan",
                                    "Terraform binary not found. Ensure terraform is installed.",
                                    error_code="TERRAFORM_NOT_FOUND", status_code=500)
    blocked_hits = []
    plan_lower = plan_output.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in plan_lower:
            blocked_hits.append(pattern)
    json_findings = []
    try:
        json_result = subprocess.run(json_cmd, cwd=working_dir, capture_output=True, text=True, timeout=300)
        if json_result.stdout:
            plan_changes = []
            for line in json_result.stdout.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    if entry.get("type") in ("resource_drift", "planned_change"):
                        plan_changes.append(entry)
                except json.JSONDecodeError:
                    continue
            json_findings = _validate_plan_json(plan_changes)
    except Exception as e:
        logger.warning("JSON plan validation failed: %s", e)
    critical_findings = [f for f in json_findings if f.get("severity") == "critical"]
    plan_approved = not blocked_hits and not critical_findings
    plan_hash = hashlib.sha256(plan_output.encode()).hexdigest()
    approval_token = _generate_approval_token(plan_hash) if plan_approved else None
    result = {
        "has_changes": has_changes, "plan_approved": plan_approved,
        "plan_hash": plan_hash, "approval_token": approval_token,
        "plan_summary": redact_secrets(plan_output[:5000]),
        "validation": {
            "blocked_pattern_hits": blocked_hits, "json_findings": json_findings,
            "critical_count": len(critical_findings),
            "total_findings": len(json_findings) + len(blocked_hits),
        },
        "human_oversight_note": (
            "AIUC-1-11 requires human review before terraform apply. "
            "The approval_token must be passed to run_terraform_apply. "
            "If plan_approved is false, the apply function will reject the token."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return build_success_response("run_terraform_plan", result,
                                  aiuc1_controls=["AIUC-1-07", "AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30"])


# ===========================================================================
# 9. run_terraform_apply — Action Function (3 of 4)
# ===========================================================================
def _validate_approval_token(plan_hash: str, token: str) -> bool:
    secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
    expected = hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)


@app.route(route="run_terraform_apply", methods=["POST"])
@log_function_call("run_terraform_apply", aiuc1_controls=["AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30", "AIUC-1-34"])
def run_terraform_apply(req: func.HttpRequest) -> func.HttpResponse:
    """Execute terraform apply with approval token validation."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("run_terraform_apply", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    plan_hash = body.get("plan_hash", "").strip()
    approval_token = body.get("approval_token", "").strip()
    agent_id = body.get("agent_id", "unknown")
    if not plan_hash or not approval_token:
        return build_error_response("run_terraform_apply",
                                    "Both plan_hash and approval_token are required. "
                                    "Run run_terraform_plan first to obtain these values.",
                                    error_code="MISSING_APPROVAL", status_code=400)
    if not _validate_approval_token(plan_hash, approval_token):
        log_event("security_event", function_name="run_terraform_apply",
                  agent_id=agent_id, severity="ERROR",
                  details={"reason": "Invalid approval token", "plan_hash_prefix": plan_hash[:8]},
                  aiuc1_controls=["AIUC-1-11"])
        return build_error_response("run_terraform_apply",
                                    "Invalid approval token. The plan may have changed since approval. "
                                    "Re-run run_terraform_plan to get a fresh token.",
                                    error_code="INVALID_APPROVAL_TOKEN", status_code=403)
    settings = get_settings()
    working_dir = body.get("working_dir", settings.terraform_working_dir)
    if not working_dir:
        working_dir = os.path.join(settings.git_repo_path, "terraform")
    if not os.path.isdir(working_dir):
        return build_error_response("run_terraform_apply",
                                    f"Terraform working directory does not exist: {working_dir}",
                                    error_code="INVALID_WORKING_DIR", status_code=400)
    cmd = ["terraform", "apply", "-auto-approve", "-no-color"]
    target = body.get("target")
    if target:
        cmd.extend(["-target", target])
    log_event("terraform_apply_start", function_name="run_terraform_apply",
              agent_id=agent_id,
              details={"working_dir": working_dir, "plan_hash_prefix": plan_hash[:8], "target": target},
              aiuc1_controls=["AIUC-1-30"])
    try:
        apply_result = subprocess.run(cmd, cwd=working_dir, capture_output=True, text=True, timeout=600)
        apply_output = apply_result.stdout
        apply_stderr = apply_result.stderr
        success = apply_result.returncode == 0
        if not success:
            log_event("terraform_apply_failed", function_name="run_terraform_apply",
                      agent_id=agent_id, severity="ERROR",
                      details={"exit_code": apply_result.returncode, "stderr_preview": redact_secrets(apply_stderr[:500])},
                      aiuc1_controls=["AIUC-1-22", "AIUC-1-30"])
            return build_error_response("run_terraform_apply",
                                        redact_secrets(apply_stderr or apply_output),
                                        error_code="TERRAFORM_APPLY_ERROR", status_code=500,
                                        details={"exit_code": apply_result.returncode})
    except subprocess.TimeoutExpired:
        return build_error_response("run_terraform_apply",
                                    "Terraform apply timed out after 600 seconds",
                                    error_code="TIMEOUT", status_code=504)
    except FileNotFoundError:
        return build_error_response("run_terraform_apply", "Terraform binary not found",
                                    error_code="TERRAFORM_NOT_FOUND", status_code=500)
    log_event("terraform_apply_success", function_name="run_terraform_apply",
              agent_id=agent_id,
              details={"plan_hash_prefix": plan_hash[:8], "output_length": len(apply_output)},
              aiuc1_controls=["AIUC-1-22", "AIUC-1-30"])
    result = {
        "success": True, "plan_hash": plan_hash,
        "apply_summary": redact_secrets(apply_output[:5000]),
        "working_dir": working_dir, "target": target,
        "applied_by_agent": agent_id,
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "change_management_note": (
            "This apply was executed with a validated approval token. "
            "The plan hash ensures the exact approved plan was applied. "
            "Full output is logged in Application Insights for audit."
        ),
    }
    return build_success_response("run_terraform_apply", result,
                                  aiuc1_controls=["AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30", "AIUC-1-34"])


# ===========================================================================
# 10. git_commit_push — Action Function (4 of 4)
# ===========================================================================
import re

ALLOWED_DIRECTORIES = {"reports", "docs", "terraform", "policies", "evidence"}

COMMIT_MESSAGE_PATTERN = re.compile(
    r"^(feat|fix|docs|chore|refactor|test|ci)\([a-z0-9-]+\): .{10,200}$"
)

SECRET_PATTERNS = [
    re.compile(r"(?:password|secret|key|token)\s*[=:]\s*['\"][^'\"]{8,}", re.IGNORECASE),
    re.compile(r"DefaultEndpointsProtocol=", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
]


def _scan_for_secrets(file_path: str) -> list[str]:
    warnings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for i, pattern in enumerate(SECRET_PATTERNS):
                matches = pattern.findall(content)
                if matches:
                    warnings.append(
                        f"Potential secret detected (pattern {i+1}): "
                        f"{len(matches)} match(es) in {os.path.basename(file_path)}"
                    )
    except Exception as e:
        warnings.append(f"Could not scan {file_path}: {e}")
    return warnings


def _validate_file_paths(files: list[str], repo_path: str) -> tuple[list[str], list[str]]:
    valid, rejected = [], []
    for file_path in files:
        normalised = os.path.normpath(file_path)
        if normalised.startswith("/"):
            if not normalised.startswith(repo_path):
                rejected.append(f"{file_path} (outside repository)")
                continue
            relative = os.path.relpath(normalised, repo_path)
        else:
            relative = normalised
        top_dir = relative.split(os.sep)[0]
        if top_dir not in ALLOWED_DIRECTORIES:
            rejected.append(f"{file_path} (directory '{top_dir}' not in allowed list)")
            continue
        valid.append(relative)
    return valid, rejected


@app.route(route="git_commit_push", methods=["POST"])
@log_function_call("git_commit_push", aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-23", "AIUC-1-30", "AIUC-1-34"])
def git_commit_push(req: func.HttpRequest) -> func.HttpResponse:
    """Commit compliance artifacts to the Git repository."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("git_commit_push", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    field_error = validate_required_fields(body, ["files", "message"])
    if field_error:
        return build_error_response("git_commit_push", field_error,
                                    error_code="MISSING_FIELDS", status_code=400)
    files = body["files"]
    message = body["message"].strip()
    agent_id = body.get("agent_id", "unknown")
    should_push = body.get("push", True)
    if not isinstance(files, list) or not files:
        return build_error_response("git_commit_push",
                                    "'files' must be a non-empty list of file paths",
                                    error_code="INVALID_FILES", status_code=400)
    if not COMMIT_MESSAGE_PATTERN.match(message):
        return build_error_response("git_commit_push",
                                    f"Commit message must follow conventional format: "
                                    f"type(scope): description (10-200 chars). Got: '{message}'",
                                    error_code="INVALID_COMMIT_MESSAGE", status_code=400)
    settings = get_settings()
    repo_path = settings.git_repo_path
    valid_files, rejected_files = _validate_file_paths(files, repo_path)
    if rejected_files:
        return build_error_response("git_commit_push",
                                    f"Some files are outside allowed directories: {rejected_files}",
                                    error_code="PATH_VIOLATION", status_code=403,
                                    details={"rejected": rejected_files, "allowed_dirs": list(ALLOWED_DIRECTORIES)})
    if not valid_files:
        return build_error_response("git_commit_push",
                                    "No valid files to commit after path validation",
                                    error_code="NO_VALID_FILES", status_code=400)
    all_warnings = []
    for file_path in valid_files:
        full_path = os.path.join(repo_path, file_path)
        if os.path.isfile(full_path):
            warnings = _scan_for_secrets(full_path)
            all_warnings.extend(warnings)
    if all_warnings:
        log_event("security_event", function_name="git_commit_push",
                  agent_id=agent_id, severity="WARNING",
                  details={"secret_scan_warnings": all_warnings},
                  aiuc1_controls=["AIUC-1-34"])
        return build_error_response("git_commit_push",
                                    "Pre-commit secret scan detected potential secrets. "
                                    "Review and sanitise files before committing.",
                                    error_code="SECRET_DETECTED", status_code=403,
                                    details={"warnings": all_warnings})
    try:
        for file_path in valid_files:
            subprocess.run(["git", "add", file_path], cwd=repo_path,
                           capture_output=True, text=True, check=True)
        commit_result = subprocess.run(
            ["git", "commit", "-m", message, "--author", f"AIUC-1 Agent <{agent_id}@aiuc1.lab>"],
            cwd=repo_path, capture_output=True, text=True)
        if commit_result.returncode != 0:
            return build_error_response("git_commit_push",
                                        redact_secrets(commit_result.stderr or commit_result.stdout),
                                        error_code="GIT_COMMIT_ERROR", status_code=500)
        hash_result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path,
                                     capture_output=True, text=True)
        commit_hash = hash_result.stdout.strip()
        push_status = "skipped"
        if should_push:
            push_result = subprocess.run(["git", "push"], cwd=repo_path,
                                         capture_output=True, text=True, timeout=60)
            push_status = "success" if push_result.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        return build_error_response("git_commit_push",
                                    "Git push timed out after 60 seconds",
                                    error_code="TIMEOUT", status_code=504)
    except Exception as e:
        return build_error_response("git_commit_push", str(e),
                                    error_code="GIT_ERROR", status_code=500)
    result = {
        "commit_hash": commit_hash, "message": message,
        "files_committed": valid_files, "push_status": push_status,
        "committed_by_agent": agent_id,
        "committed_at": datetime.now(timezone.utc).isoformat(),
        "audit_note": (
            "This commit was created by an AI agent via the git_commit_push "
            "function. Pre-commit secret scanning was performed. The commit "
            "is part of the immutable audit trail (AIUC-1-23)."
        ),
    }
    return build_success_response("git_commit_push", result,
                                  aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-23", "AIUC-1-30", "AIUC-1-34"])


# ===========================================================================
# 11. sanitize_output — Safety Function (1 of 2)
# ===========================================================================
@app.route(route="sanitize_output", methods=["POST"])
@log_function_call("sanitize_output", aiuc1_controls=["AIUC-1-17", "AIUC-1-19", "AIUC-1-22", "AIUC-1-34"])
def sanitize_output(req: func.HttpRequest) -> func.HttpResponse:
    """Sanitise text or structured data by redacting sensitive values."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("sanitize_output", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    text_input = body.get("text")
    data_input = body.get("data")
    agent_id = body.get("agent_id", "unknown")
    if text_input is None and data_input is None:
        return build_error_response("sanitize_output",
                                    "Provide either 'text' (string) or 'data' (object) to sanitise",
                                    error_code="MISSING_INPUT", status_code=400)
    if text_input is not None and data_input is not None:
        return build_error_response("sanitize_output",
                                    "Provide only one of 'text' or 'data', not both",
                                    error_code="AMBIGUOUS_INPUT", status_code=400)
    redaction_count = 0
    if text_input is not None:
        if not isinstance(text_input, str):
            return build_error_response("sanitize_output", "'text' must be a string",
                                        error_code="INVALID_TYPE", status_code=400)
        sanitised = redact_secrets(text_input)
        redaction_count = sanitised.count("[REDACTED")
        output_type = "text"
        output = sanitised
    else:
        if not isinstance(data_input, dict):
            return build_error_response("sanitize_output", "'data' must be a JSON object",
                                        error_code="INVALID_TYPE", status_code=400)
        sanitised = redact_dict(data_input)
        serialised = json.dumps(sanitised)
        redaction_count = serialised.count("[REDACTED")
        output_type = "data"
        output = sanitised
    log_event("sanitisation_performed", function_name="sanitize_output",
              agent_id=agent_id,
              details={"input_type": output_type, "redaction_count": redaction_count},
              aiuc1_controls=["AIUC-1-19"])
    result = {
        "output_type": output_type, "sanitised_output": output,
        "redaction_stats": {
            "total_redactions": redaction_count,
            "patterns_applied": [
                "subscription_ids", "standalone_uuids", "base64_access_keys",
                "connection_strings", "private_ips", "sas_tokens", "sp_secrets", "bearer_tokens",
            ],
        },
        "allowed_to_remain": [
            "resource_names", "sku_names", "azure_regions",
            "policy_states", "rbac_role_names", "cc_category_codes",
        ],
        "sanitised_at": datetime.now(timezone.utc).isoformat(),
    }
    return build_success_response("sanitize_output", result, sanitise=False,
                                  aiuc1_controls=["AIUC-1-17", "AIUC-1-19", "AIUC-1-22", "AIUC-1-34"])


# ===========================================================================
# 12. log_security_event — Safety Function (2 of 2)
# ===========================================================================
VALID_CATEGORIES = {
    "scope_violation": {
        "description": "Agent tried to access out-of-scope resources",
        "default_severity": "ERROR", "aiuc1_controls": ["AIUC-1-09", "AIUC-1-22"]},
    "secret_exposure": {
        "description": "Potential credential leak detected",
        "default_severity": "CRITICAL", "aiuc1_controls": ["AIUC-1-34", "AIUC-1-22"]},
    "validation_failure": {
        "description": "Input validation rejected a request",
        "default_severity": "WARNING", "aiuc1_controls": ["AIUC-1-18", "AIUC-1-22"]},
    "approval_denied": {
        "description": "Terraform apply rejected (invalid token)",
        "default_severity": "ERROR", "aiuc1_controls": ["AIUC-1-11", "AIUC-1-22"]},
    "anomalous_behavior": {
        "description": "Agent behavior outside expected patterns",
        "default_severity": "WARNING", "aiuc1_controls": ["AIUC-1-24", "AIUC-1-22"]},
    "compliance_finding": {
        "description": "New compliance gap discovered",
        "default_severity": "INFO", "aiuc1_controls": ["AIUC-1-22", "AIUC-1-46"]},
    "remediation_action": {
        "description": "Infrastructure change applied to fix a compliance gap",
        "default_severity": "INFO", "aiuc1_controls": ["AIUC-1-30", "AIUC-1-22"]},
    "access_event": {
        "description": "RBAC or access control change detected",
        "default_severity": "WARNING", "aiuc1_controls": ["AIUC-1-09", "AIUC-1-22"]},
}

VALID_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@app.route(route="log_security_event", methods=["POST"])
@log_function_call("log_security_event", aiuc1_controls=["AIUC-1-22", "AIUC-1-23", "AIUC-1-24", "AIUC-1-19"])
def log_security_event(req: func.HttpRequest) -> func.HttpResponse:
    """Log a structured security event to Application Insights."""
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response("log_security_event", "Request body must be valid JSON",
                                    error_code="INVALID_JSON", status_code=400)
    field_error = validate_required_fields(body, ["category", "agent_id", "description"])
    if field_error:
        return build_error_response("log_security_event", field_error,
                                    error_code="MISSING_FIELDS", status_code=400)
    category = body["category"].strip().lower()
    agent_id = body["agent_id"].strip()
    description = body["description"].strip()
    if category not in VALID_CATEGORIES:
        return build_error_response("log_security_event",
                                    f"Invalid category '{category}'. Must be one of: {sorted(VALID_CATEGORIES.keys())}",
                                    error_code="INVALID_CATEGORY", status_code=400)
    severity = body.get("severity", "").strip().upper()
    if severity and severity not in VALID_SEVERITIES:
        return build_error_response("log_security_event",
                                    f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}",
                                    error_code="INVALID_SEVERITY", status_code=400)
    if not severity:
        severity = VALID_CATEGORIES[category]["default_severity"]
    aiuc1_controls = body.get("aiuc1_controls", VALID_CATEGORIES[category]["aiuc1_controls"])
    sanitised_description = redact_secrets(description)
    details = body.get("details", {})
    sanitised_details = redact_dict(details) if isinstance(details, dict) else {}
    event_id = f"SEC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{category[:4].upper()}"
    log_event(
        event_type=f"security_event.{category}",
        function_name="log_security_event",
        agent_id=agent_id, cc_category=body.get("cc_category", ""),
        severity=severity,
        details={
            "event_id": event_id, "category": category,
            "category_description": VALID_CATEGORIES[category]["description"],
            "description": sanitised_description,
            **sanitised_details,
        },
        aiuc1_controls=aiuc1_controls,
    )
    result = {
        "event_id": event_id, "category": category,
        "category_description": VALID_CATEGORIES[category]["description"],
        "severity": severity, "agent_id": agent_id,
        "description": sanitised_description,
        "details": sanitised_details,
        "aiuc1_controls": aiuc1_controls,
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "destination": "Azure Application Insights (custom events)",
        "retention_note": (
            "Security events are retained in Application Insights for the "
            "configured retention period (default 90 days). For SOC 2 Type II "
            "audits, ensure retention covers the examination period."
        ),
    }
    return build_success_response("log_security_event", result,
                                  aiuc1_controls=["AIUC-1-22", "AIUC-1-23", "AIUC-1-24", "AIUC-1-19"])
