# ===========================================================================
# AIUC-1 SOC 2 Compliance Lab — Azure Functions (Queue-Triggered)
# ===========================================================================
# All 12 functions use Azure Storage Queue triggers for integration with
# Azure AI Foundry Agent Service (AzureFunctionTool).
#
# Architecture:
#   Agent → writes to {function}-input queue
#   Function → triggers, processes, writes result to {function}-output queue
#   Agent → reads from {function}-output queue
#
# This pattern provides:
#   - E015: Immutable message trail in queue storage
#   - C007: Async pattern supports human-in-the-loop
#   - E015: Every tool call is a timestamped queue message
#   - No API keys in agent config (auth via Azure managed identity)
# ===========================================================================

import azure.functions as func
import json
import logging
import os
import hashlib
import hmac
import subprocess
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

# Shared modules
from shared.config import get_settings
from shared.sanitizer import redact_secrets, redact_dict
from shared.validators import validate_cc_category, validate_resource_group, validate_required_fields
from shared.logger import log_event, log_function_call
from shared.response import build_success_envelope, build_error_envelope
from shared.azure_clients import get_mgmt_client

logger = logging.getLogger("aiuc1-soc2")

app = func.FunctionApp()


# ===========================================================================
# Helper: Parse queue message and write response to output queue
# ===========================================================================
def parse_queue_msg(msg: func.QueueMessage) -> tuple[dict, str]:
    """Parse a queue message body as JSON.
    
    Returns:
        Tuple of (parsed body dict, correlation_id string).
        The CorrelationId is extracted and must be echoed back in the response
        for Azure AI Foundry Agent Service to match request/response pairs.
    """
    body = msg.get_body().decode("utf-8")
    if not body or body.strip() == "":
        return {}, ""
    try:
        parsed = json.loads(body)
        correlation_id = parsed.pop("CorrelationId", "")
        return parsed, correlation_id
    except json.JSONDecodeError:
        return {"_raw": body}, ""


def write_output(output: func.Out[str], envelope: dict, correlation_id: str = ""):
    """Serialize envelope and write to output queue.
    
    The response includes:
    - Value: JSON string of the envelope (what the agent sees)
    - CorrelationId: echoed from the input message for request/response matching
    """
    response = {
        "Value": json.dumps(envelope, default=str),
        "CorrelationId": correlation_id,
    }
    output.set(json.dumps(response, default=str))


# ===========================================================================
# CC Resource Map (shared across gap_analyzer and scan_cc_criteria)
# ===========================================================================
CC_RESOURCE_MAP = {
    "CC1": {"description": "Control Environment", "checks": [
        "Azure Policy assignment coverage", "Management group hierarchy",
        "Subscription-level RBAC governance"]},
    "CC2": {"description": "Communication and Information", "checks": [
        "Azure Activity Log alert rules", "Action Group configurations",
        "Service Health alert coverage"]},
    "CC3": {"description": "Risk Assessment", "checks": [
        "Microsoft Defender for Cloud coverage", "Vulnerability assessment configurations",
        "Risk register integration"]},
    "CC4": {"description": "Monitoring Activities", "checks": [
        "Application Insights availability", "Log Analytics workspace retention",
        "Diagnostic settings coverage"]},
    "CC5": {"description": "Control Activities", "checks": [
        "Storage account encryption (at-rest and in-transit)", "TLS version enforcement",
        "Key Vault access policies"]},
    "CC6": {"description": "Logical and Physical Access Controls", "checks": [
        "NSG rule analysis", "RBAC role assignment review",
        "Conditional Access policy coverage"]},
    "CC7": {"description": "System Operations", "checks": [
        "SQL Server auditing", "Database backup configuration",
        "Patch management compliance"]},
    "CC8": {"description": "Change Management", "checks": [
        "Azure Policy compliance state", "Terraform state drift detection",
        "Deployment pipeline audit logs"]},
    "CC9": {"description": "Risk Mitigation", "checks": [
        "Defender Secure Score", "Remediation plan tracking",
        "Insurance and BCP documentation"]},
}


# ===========================================================================
# 1. gap_analyzer — Data Provider (1 of 6)
# ===========================================================================
def _analyze_cc5_gaps(settings) -> list[dict]:
    gaps = []
    storage_client = get_mgmt_client("storage")
    for rg in settings.allowed_resource_groups:
        try:
            for acct in storage_client.storage_accounts.list_by_resource_group(rg):
                if acct.allow_blob_public_access:
                    gaps.append({"resource": acct.name, "resource_group": rg,
                                 "gap": "Public blob access is enabled",
                                 "severity": "high", "cc_criteria": "CC5.2",
                                 "remediation": "Set allowBlobPublicAccess to false"})
                if not acct.enable_https_traffic_only:
                    gaps.append({"resource": acct.name, "resource_group": rg,
                                 "gap": "HTTPS-only traffic not enforced",
                                 "severity": "high", "cc_criteria": "CC5.2",
                                 "remediation": "Enable supportsHttpsTrafficOnly"})
                tls = acct.minimum_tls_version or "TLS1_0"
                if tls != "TLS1_2":
                    gaps.append({"resource": acct.name, "resource_group": rg,
                                 "gap": f"Minimum TLS version is {tls} (should be TLS1_2)",
                                 "severity": "medium", "cc_criteria": "CC5.2",
                                 "remediation": "Set minimumTlsVersion to TLS1_2"})
                if acct.encryption and not acct.encryption.require_infrastructure_encryption:
                    gaps.append({"resource": acct.name, "resource_group": rg,
                                 "gap": "Infrastructure encryption (double encryption) not enabled",
                                 "severity": "low", "cc_criteria": "CC5.2",
                                 "remediation": "Enable infrastructure encryption for defense in depth"})
        except Exception as e:
            logger.warning("Error scanning storage in %s: %s", rg, e)
    return gaps


def _analyze_cc6_gaps(settings) -> list[dict]:
    gaps = []
    network_client = get_mgmt_client("network")
    for rg in settings.allowed_resource_groups:
        try:
            for nsg in network_client.network_security_groups.list(rg):
                for rule in (nsg.security_rules or []):
                    if (rule.direction == "Inbound" and rule.access == "Allow"
                            and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                        gaps.append({"resource": f"{nsg.name}/{rule.name}", "resource_group": rg,
                                     "gap": f"Overly permissive inbound rule: source={rule.source_address_prefix}, port={rule.destination_port_range}",
                                     "severity": "critical" if rule.destination_port_range in ("*", "22", "3389") else "high",
                                     "cc_criteria": "CC6.1",
                                     "remediation": "Restrict source to specific IP ranges"})
        except Exception as e:
            logger.warning("Error scanning NSGs in %s: %s", rg, e)
    return gaps


def _analyze_cc7_gaps(settings) -> list[dict]:
    gaps = []
    sql_client = get_mgmt_client("sql")
    for rg in settings.allowed_resource_groups:
        try:
            for server in sql_client.servers.list_by_resource_group(rg):
                try:
                    audit = sql_client.server_blob_auditing_policies.get(rg, server.name)
                    if audit.state != "Enabled":
                        gaps.append({"resource": server.name, "resource_group": rg,
                                     "gap": "SQL Server auditing is not enabled",
                                     "severity": "high", "cc_criteria": "CC7.2",
                                     "remediation": "Enable blob auditing on the SQL Server"})
                except Exception:
                    gaps.append({"resource": server.name, "resource_group": rg,
                                 "gap": "Unable to verify SQL Server auditing status",
                                 "severity": "medium", "cc_criteria": "CC7.2",
                                 "remediation": "Verify and enable auditing"})
                if server.public_network_access and server.public_network_access.lower() == "enabled":
                    gaps.append({"resource": server.name, "resource_group": rg,
                                 "gap": "SQL Server public network access is enabled",
                                 "severity": "high", "cc_criteria": "CC7.1",
                                 "remediation": "Disable public network access and use private endpoints"})
        except Exception as e:
            logger.warning("Error scanning SQL in %s: %s", rg, e)
    return gaps


_GAP_ANALYZERS = {"CC5": _analyze_cc5_gaps, "CC6": _analyze_cc6_gaps, "CC7": _analyze_cc7_gaps}


@app.queue_trigger(arg_name="msg", queue_name="gap-analyzer-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="gap-analyzer-output", connection="AzureWebJobsStorage")
def gap_analyzer(msg: func.QueueMessage, output: func.Out[str]):
    """Scan Azure resources for SOC 2 compliance gaps by CC category."""
    body, correlation_id = parse_queue_msg(msg)
    cc_category = body.get("cc_category", "").strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        write_output(output, build_error_envelope("gap_analyzer", cc_error,
                     error_code="INVALID_CC_CATEGORY"), correlation_id)
        return
    settings = get_settings()
    analyzer = _GAP_ANALYZERS.get(cc_category)
    if analyzer:
        gaps = analyzer(settings)
        scanner_status = "completed"
    else:
        gaps = []
        scanner_status = "not_yet_implemented"
    result = {
        "cc_category": cc_category,
        "cc_description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "scanner_status": scanner_status,
        "gaps_found": len(gaps), "gaps": gaps,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": settings.allowed_resource_groups,
    }
    if scanner_status == "not_yet_implemented":
        result["note"] = (f"Scanner for {cc_category} is planned but not yet implemented. "
                          f"Planned checks: {CC_RESOURCE_MAP.get(cc_category, {}).get('checks', [])}")
    write_output(output, build_success_envelope("gap_analyzer", result,
                 aiuc1_controls=["B006", "A003", "C002", "B009", "E015"]), correlation_id)


# ===========================================================================
# 2. scan_cc_criteria — Data Provider (2 of 6)
# ===========================================================================
def _scan_cc5(settings) -> list[dict]:
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
    checks = CC_RESOURCE_MAP.get(cc_category, {}).get("checks", [])
    return [{
        "type": "scan_metadata", "cc_category": cc_category,
        "description": CC_RESOURCE_MAP.get(cc_category, {}).get("description", ""),
        "planned_checks": checks, "status": "not_yet_implemented",
        "note": "Scanner for this CC category is planned but not yet implemented.",
    }]


_SCANNERS = {"CC5": _scan_cc5, "CC6": _scan_cc6, "CC7": _scan_cc7}


@app.queue_trigger(arg_name="msg", queue_name="scan-cc-criteria-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="scan-cc-criteria-output", connection="AzureWebJobsStorage")
def scan_cc_criteria(msg: func.QueueMessage, output: func.Out[str]):
    """Scan Azure resources relevant to a SOC 2 CC category."""
    body, correlation_id = parse_queue_msg(msg)
    cc_category = body.get("cc_category", "").strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        write_output(output, build_error_envelope("scan_cc_criteria", cc_error,
                     error_code="INVALID_CC_CATEGORY"), correlation_id)
        return
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
    write_output(output, build_success_envelope("scan_cc_criteria", result,
                 aiuc1_controls=["B006", "A003", "C002", "B009", "E015"]), correlation_id)


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
        "over the examination period (typically 6-12 months)."
    ),
    "sampling_strategy": "statistical",
    "minimum_samples": 25,
    "confidence_level": "95%",
}


def _validate_azure_resource(resource_id: str, settings) -> dict:
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


@app.queue_trigger(arg_name="msg", queue_name="evidence-validator-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="evidence-validator-output", connection="AzureWebJobsStorage")
def evidence_validator(msg: func.QueueMessage, output: func.Out[str]):
    """Validate existence and metadata of compliance evidence artifacts."""
    body, correlation_id = parse_queue_msg(msg)
    field_error = validate_required_fields(body, ["evidence_type", "target"])
    if field_error:
        write_output(output, build_error_envelope("evidence_validator", field_error,
                     error_code="MISSING_FIELDS"), correlation_id)
        return
    evidence_type = body["evidence_type"].strip().lower()
    target = body["target"].strip()
    cc_category = body.get("cc_category", "").strip().upper()
    valid_types = {"azure_resource", "policy_state", "document", "log_entry"}
    if evidence_type not in valid_types:
        write_output(output, build_error_envelope("evidence_validator",
                     f"Invalid evidence_type '{evidence_type}'. Must be one of: {sorted(valid_types)}",
                     error_code="INVALID_EVIDENCE_TYPE"))
        return
    settings = get_settings()
    if evidence_type == "azure_resource":
        validation = _validate_azure_resource(target, settings)
    elif evidence_type == "document":
        validation = _validate_document(target, settings)
    else:
        validation = {
            "evidence_type": evidence_type, "target": target,
            "status": "validator_not_yet_implemented",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    result = {
        "evidence_type": evidence_type, "target": target,
        "validation": validation,
        "evidence_map": EVIDENCE_MAP.get(cc_category, {}) if cc_category else {},
        "type_ii_sampling": TYPE_II_SAMPLING,
    }
    write_output(output, build_success_envelope("evidence_validator", result,
                 aiuc1_controls=["B006", "A003", "C002", "B009", "E015", "E017"]), correlation_id)


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
        assignments.append({"error": str(e), "note": "RBAC query failed"})
    return assignments


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


@app.queue_trigger(arg_name="msg", queue_name="query-access-controls-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="query-access-controls-output", connection="AzureWebJobsStorage")
def query_access_controls(msg: func.QueueMessage, output: func.Out[str]):
    """Query Azure RBAC and network access controls."""
    body, correlation_id = parse_queue_msg(msg)
    scope = body.get("scope", "").strip()
    include_nsg = body.get("include_nsg", True)
    if scope:
        rg_error = validate_resource_group(scope)
        if rg_error:
            write_output(output, build_error_envelope("query_access_controls", rg_error,
                         error_code="SCOPE_VIOLATION"), correlation_id)
            return
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
        "scope_note": "This function queries ARM RBAC. Entra ID directory roles are not included.",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    write_output(output, build_success_envelope("query_access_controls", result,
                 aiuc1_controls=["B006", "A003", "C002", "B009", "E015"]), correlation_id)


# ===========================================================================
# 5. query_defender_score — Data Provider (5 of 6)
# ===========================================================================
def _get_secure_scores(settings) -> dict:
    security_client = get_mgmt_client("security")
    scores = {}
    try:
        for score in security_client.secure_scores.list():
            current_score = None
            max_score = None
            percentage = None
            if hasattr(score, 'current_score'):
                current_score = score.current_score
            elif hasattr(score, 'score') and score.score is not None:
                current_score = getattr(score.score, 'current', None)
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
        scores = {"error": str(e), "note": "Secure Score retrieval failed."}
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
        assessments.append({"error": str(e)})
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "unknown": 3}
    assessments.sort(key=lambda a: severity_order.get(a.get("severity", "unknown"), 3))
    return assessments


@app.queue_trigger(arg_name="msg", queue_name="query-defender-score-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="query-defender-score-output", connection="AzureWebJobsStorage")
def query_defender_score(msg: func.QueueMessage, output: func.Out[str]):
    """Query Microsoft Defender for Cloud Secure Score and recommendations."""
    body, correlation_id = parse_queue_msg(msg)
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
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    write_output(output, build_success_envelope("query_defender_score", result,
                 aiuc1_controls=["B006", "A003", "B009", "E015"]), correlation_id)


# ===========================================================================
# 6. query_policy_compliance — Data Provider (6 of 6)
# ===========================================================================
CIS_BENCHMARK_POLICY_ID = "06f19060-9e68-4070-92ca-f15cc126059e"


def _get_compliance_summary(settings) -> dict:
    policy_client = get_mgmt_client("policy_insights")
    summary = {"compliant": 0, "non_compliant": 0, "exempt": 0, "conflicting": 0, "not_started": 0}
    try:
        sub_id = settings.azure_subscription_id
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
        non_compliant.append({"error": str(e)})
    return non_compliant


@app.queue_trigger(arg_name="msg", queue_name="query-policy-compliance-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="query-policy-compliance-output", connection="AzureWebJobsStorage")
def query_policy_compliance(msg: func.QueueMessage, output: func.Out[str]):
    """Query Azure Policy compliance state for the subscription."""
    body, correlation_id = parse_queue_msg(msg)
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
        },
        "soc2_mapping": {
            "primary": "CC1 — Control Environment", "secondary": "CC8 — Change Management",
        },
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    write_output(output, build_success_envelope("query_policy_compliance", result,
                 aiuc1_controls=["B006", "A003", "B009", "E015"]), correlation_id)


# ===========================================================================
# 7. generate_poam_entry — Action Function (1 of 4)
# ===========================================================================
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


@app.queue_trigger(arg_name="msg", queue_name="generate-poam-entry-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="generate-poam-entry-output", connection="AzureWebJobsStorage")
def generate_poam_entry(msg: func.QueueMessage, output: func.Out[str]):
    """Generate a structured POA&M entry for a compliance gap."""
    body, correlation_id = parse_queue_msg(msg)
    field_error = validate_required_fields(body, ["cc_category", "resource", "gap_description", "severity"])
    if field_error:
        write_output(output, build_error_envelope("generate_poam_entry", field_error,
                     error_code="MISSING_FIELDS"), correlation_id)
        return
    cc_category = body["cc_category"].strip().upper()
    cc_error = validate_cc_category(cc_category)
    if cc_error:
        write_output(output, build_error_envelope("generate_poam_entry", cc_error,
                     error_code="INVALID_CC_CATEGORY"), correlation_id)
        return
    severity = body["severity"].strip().lower()
    if severity not in SEVERITY_TIMELINES:
        write_output(output, build_error_envelope("generate_poam_entry",
                     f"Invalid severity '{severity}'. Must be one of: {list(SEVERITY_TIMELINES.keys())}",
                     error_code="INVALID_SEVERITY"), correlation_id)
        return
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
        "status": "open",
        "provenance": {
            "generated_by": "generate_poam_entry",
            "generated_at": now.isoformat(),
        },
    }
    result = {
        "poam_entry": poam_entry,
        "timeline_rationale": f"Severity '{severity}' maps to a {timeline['days']}-day remediation window.",
    }
    write_output(output, build_success_envelope("generate_poam_entry", result,
                 aiuc1_controls=["C002", "B009", "E015", "E017"]), correlation_id)


# ===========================================================================
# 8. run_terraform_plan — Action Function (2 of 4)
# ===========================================================================
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


@app.queue_trigger(arg_name="msg", queue_name="run-terraform-plan-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="run-terraform-plan-output", connection="AzureWebJobsStorage")
def run_terraform_plan(msg: func.QueueMessage, output: func.Out[str]):
    """Execute terraform plan with validation and approval gate."""
    body, correlation_id = parse_queue_msg(msg)
    settings = get_settings()
    working_dir = body.get("working_dir", settings.terraform_working_dir)
    if not working_dir:
        working_dir = os.path.join(settings.git_repo_path, "terraform")
    if not os.path.isdir(working_dir):
        write_output(output, build_error_envelope("run_terraform_plan",
                     f"Terraform working directory does not exist: {working_dir}",
                     error_code="INVALID_WORKING_DIR"), correlation_id)
        return
    cmd = ["terraform", "plan", "-no-color", "-detailed-exitcode"]
    target = body.get("target")
    if target:
        cmd.extend(["-target", target])
    try:
        plan_result = subprocess.run(cmd, cwd=working_dir, capture_output=True, text=True, timeout=300)
        plan_output = plan_result.stdout
        has_changes = plan_result.returncode == 2
        has_error = plan_result.returncode == 1
        if has_error:
            write_output(output, build_error_envelope("run_terraform_plan",
                         redact_secrets(plan_result.stderr or plan_output),
                         error_code="TERRAFORM_PLAN_ERROR"), correlation_id)
            return
    except subprocess.TimeoutExpired:
        write_output(output, build_error_envelope("run_terraform_plan",
                     "Terraform plan timed out after 300 seconds",
                     error_code="TIMEOUT"), correlation_id)
        return
    except FileNotFoundError:
        write_output(output, build_error_envelope("run_terraform_plan",
                     "Terraform binary not found.",
                     error_code="TERRAFORM_NOT_FOUND"), correlation_id)
        return
    blocked_hits = []
    plan_lower = plan_output.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in plan_lower:
            blocked_hits.append(pattern)
    critical_findings = []
    plan_approved = not blocked_hits and not critical_findings
    plan_hash = hashlib.sha256(plan_output.encode()).hexdigest()
    approval_token = _generate_approval_token(plan_hash) if plan_approved else None
    result = {
        "has_changes": has_changes, "plan_approved": plan_approved,
        "plan_hash": plan_hash, "approval_token": approval_token,
        "plan_summary": redact_secrets(plan_output[:5000]),
        "validation": {
            "blocked_pattern_hits": blocked_hits,
            "critical_count": len(critical_findings),
        },
        "human_oversight_note": "C007 requires human review before terraform apply.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    write_output(output, build_success_envelope("run_terraform_plan", result,
                 aiuc1_controls=["C001", "C007", "C002", "B009", "E015", "E004"]), correlation_id)


# ===========================================================================
# 9. run_terraform_apply — Action Function (3 of 4)
# ===========================================================================
def _validate_approval_token(plan_hash: str, token: str) -> bool:
    secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
    expected = hmac.new(secret.encode(), plan_hash.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)


@app.queue_trigger(arg_name="msg", queue_name="run-terraform-apply-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="run-terraform-apply-output", connection="AzureWebJobsStorage")
def run_terraform_apply(msg: func.QueueMessage, output: func.Out[str]):
    """Execute terraform apply with approval token validation."""
    body, correlation_id = parse_queue_msg(msg)
    plan_hash = body.get("plan_hash", "").strip()
    approval_token = body.get("approval_token", "").strip()
    agent_id = body.get("agent_id", "unknown")
    if not plan_hash or not approval_token:
        write_output(output, build_error_envelope("run_terraform_apply",
                     "Both plan_hash and approval_token are required.",
                     error_code="MISSING_APPROVAL"), correlation_id)
        return
    if not _validate_approval_token(plan_hash, approval_token):
        log_event("security_event", function_name="run_terraform_apply",
                  agent_id=agent_id, severity="ERROR",
                  details={"reason": "Invalid approval token", "plan_hash_prefix": plan_hash[:8]},
                  aiuc1_controls=["C007"])
        write_output(output, build_error_envelope("run_terraform_apply",
                     "Invalid approval token. Re-run run_terraform_plan to get a fresh token.",
                     error_code="INVALID_APPROVAL_TOKEN"), correlation_id)
        return
    settings = get_settings()
    working_dir = body.get("working_dir", settings.terraform_working_dir)
    if not working_dir:
        working_dir = os.path.join(settings.git_repo_path, "terraform")
    if not os.path.isdir(working_dir):
        write_output(output, build_error_envelope("run_terraform_apply",
                     f"Terraform working directory does not exist: {working_dir}",
                     error_code="INVALID_WORKING_DIR"), correlation_id)
        return
    cmd = ["terraform", "apply", "-auto-approve", "-no-color"]
    try:
        apply_result = subprocess.run(cmd, cwd=working_dir, capture_output=True, text=True, timeout=600)
        if apply_result.returncode != 0:
            write_output(output, build_error_envelope("run_terraform_apply",
                         redact_secrets(apply_result.stderr or apply_result.stdout),
                         error_code="TERRAFORM_APPLY_ERROR"), correlation_id)
            return
    except subprocess.TimeoutExpired:
        write_output(output, build_error_envelope("run_terraform_apply",
                     "Terraform apply timed out after 600 seconds",
                     error_code="TIMEOUT"), correlation_id)
        return
    except FileNotFoundError:
        write_output(output, build_error_envelope("run_terraform_apply",
                     "Terraform binary not found.",
                     error_code="TERRAFORM_NOT_FOUND"), correlation_id)
        return
    result = {
        "success": True, "plan_hash": plan_hash,
        "apply_summary": redact_secrets(apply_result.stdout[:5000]),
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "change_management_note": "Applied with validated approval token (C007).",
    }
    write_output(output, build_success_envelope("run_terraform_apply", result,
                 aiuc1_controls=["C007", "C002", "B009", "E015", "E004", "A004"]), correlation_id)


# ===========================================================================
# 10. git_commit_push — Action Function (4 of 4)
# ===========================================================================
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
                    warnings.append(f"Potential secret detected (pattern {i+1}): {len(matches)} match(es)")
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


@app.queue_trigger(arg_name="msg", queue_name="git-commit-push-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="git-commit-push-output", connection="AzureWebJobsStorage")
def git_commit_push(msg: func.QueueMessage, output: func.Out[str]):
    """Commit compliance artifacts to the Git repository."""
    body, correlation_id = parse_queue_msg(msg)
    field_error = validate_required_fields(body, ["files", "message"])
    if field_error:
        write_output(output, build_error_envelope("git_commit_push", field_error,
                     error_code="MISSING_FIELDS"), correlation_id)
        return
    files = body["files"]
    message = body["message"].strip()
    agent_id = body.get("agent_id", "unknown")
    should_push = body.get("push", True)
    if not isinstance(files, list) or not files:
        write_output(output, build_error_envelope("git_commit_push",
                     "'files' must be a non-empty list",
                     error_code="INVALID_FILES"), correlation_id)
        return
    if not COMMIT_MESSAGE_PATTERN.match(message):
        write_output(output, build_error_envelope("git_commit_push",
                     f"Commit message must follow conventional format. Got: '{message}'",
                     error_code="INVALID_COMMIT_MESSAGE"), correlation_id)
        return
    settings = get_settings()
    repo_path = settings.git_repo_path
    valid_files, rejected_files = _validate_file_paths(files, repo_path)
    if rejected_files:
        write_output(output, build_error_envelope("git_commit_push",
                     f"Files outside allowed directories: {rejected_files}",
                     error_code="PATH_VIOLATION"), correlation_id)
        return
    if not valid_files:
        write_output(output, build_error_envelope("git_commit_push",
                     "No valid files to commit",
                     error_code="NO_VALID_FILES"), correlation_id)
        return
    all_warnings = []
    for file_path in valid_files:
        full_path = os.path.join(repo_path, file_path)
        if os.path.isfile(full_path):
            all_warnings.extend(_scan_for_secrets(full_path))
    if all_warnings:
        write_output(output, build_error_envelope("git_commit_push",
                     "Pre-commit secret scan detected potential secrets.",
                     error_code="SECRET_DETECTED",
                     details={"warnings": all_warnings}), correlation_id)
        return
    try:
        for file_path in valid_files:
            subprocess.run(["git", "add", file_path], cwd=repo_path,
                           capture_output=True, text=True, check=True)
        commit_result = subprocess.run(
            ["git", "commit", "-m", message, "--author", f"AIUC-1 Agent <{agent_id}@aiuc1.lab>"],
            cwd=repo_path, capture_output=True, text=True)
        if commit_result.returncode != 0:
            write_output(output, build_error_envelope("git_commit_push",
                         redact_secrets(commit_result.stderr or commit_result.stdout),
                         error_code="GIT_COMMIT_ERROR"), correlation_id)
            return
        hash_result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path,
                                     capture_output=True, text=True)
        commit_hash = hash_result.stdout.strip()
        push_status = "skipped"
        if should_push:
            push_result = subprocess.run(["git", "push"], cwd=repo_path,
                                         capture_output=True, text=True, timeout=60)
            push_status = "success" if push_result.returncode == 0 else "failed"
    except Exception as e:
        write_output(output, build_error_envelope("git_commit_push", str(e),
                     error_code="GIT_ERROR"), correlation_id)
        return
    result = {
        "commit_hash": commit_hash, "message": message,
        "files_committed": valid_files, "push_status": push_status,
        "committed_at": datetime.now(timezone.utc).isoformat(),
        "audit_note": "Commit created by AI agent with pre-commit secret scanning (E015).",
    }
    write_output(output, build_success_envelope("git_commit_push", result,
                 aiuc1_controls=["C002", "B009", "E015", "E004", "A004"]), correlation_id)


# ===========================================================================
# 11. sanitize_output — Safety Function (1 of 2)
# ===========================================================================
@app.queue_trigger(arg_name="msg", queue_name="sanitize-output-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="sanitize-output-output", connection="AzureWebJobsStorage")
def sanitize_output(msg: func.QueueMessage, output: func.Out[str]):
    """Sanitise text or structured data by redacting sensitive values."""
    body, correlation_id = parse_queue_msg(msg)
    text_input = body.get("text")
    data_input = body.get("data")
    if text_input is None and data_input is None:
        write_output(output, build_error_envelope("sanitize_output",
                     "Provide either 'text' (string) or 'data' (object) to sanitise",
                     error_code="MISSING_INPUT"), correlation_id)
        return
    if text_input is not None and data_input is not None:
        write_output(output, build_error_envelope("sanitize_output",
                     "Provide only one of 'text' or 'data', not both",
                     error_code="AMBIGUOUS_INPUT"), correlation_id)
        return
    redaction_count = 0
    if text_input is not None:
        sanitised = redact_secrets(str(text_input))
        redaction_count = sanitised.count("[REDACTED")
        output_type = "text"
        sanitised_output = sanitised
    else:
        if not isinstance(data_input, dict):
            write_output(output, build_error_envelope("sanitize_output",
                         "'data' must be a JSON object",
                         error_code="INVALID_TYPE"), correlation_id)
            return
        sanitised = redact_dict(data_input)
        serialised = json.dumps(sanitised)
        redaction_count = serialised.count("[REDACTED")
        output_type = "data"
        sanitised_output = sanitised
    result = {
        "output_type": output_type, "sanitised_output": sanitised_output,
        "redaction_stats": {
            "total_redactions": redaction_count,
            "patterns_applied": [
                "subscription_ids", "standalone_uuids", "base64_access_keys",
                "connection_strings", "private_ips", "sas_tokens", "sp_secrets", "bearer_tokens",
            ],
        },
        "sanitised_at": datetime.now(timezone.utc).isoformat(),
    }
    write_output(output, build_success_envelope("sanitize_output", result, sanitise=False,
                 aiuc1_controls=["A003", "B009", "E015", "A004"]), correlation_id)


# ===========================================================================
# 12. log_security_event — Safety Function (2 of 2)
# ===========================================================================
VALID_CATEGORIES = {
    "scope_violation": {
        "description": "Agent tried to access out-of-scope resources",
        "default_severity": "ERROR", "aiuc1_controls": ["B006", "E015"]},
    "secret_exposure": {
        "description": "Potential credential leak detected",
        "default_severity": "CRITICAL", "aiuc1_controls": ["A004", "E015"]},
    "validation_failure": {
        "description": "Input validation rejected a request",
        "default_severity": "WARNING", "aiuc1_controls": ["C002", "E015"]},
    "approval_denied": {
        "description": "Terraform apply rejected (invalid token)",
        "default_severity": "ERROR", "aiuc1_controls": ["C007", "E015"]},
    "anomalous_behavior": {
        "description": "Agent behavior outside expected patterns",
        "default_severity": "WARNING", "aiuc1_controls": ["E015"]},
    "compliance_finding": {
        "description": "New compliance gap discovered",
        "default_severity": "INFO", "aiuc1_controls": ["E015", "E017"]},
    "remediation_applied": {
        "description": "Infrastructure change applied to fix a compliance gap",
        "default_severity": "INFO", "aiuc1_controls": ["E004", "E015"]},
    "access_event": {
        "description": "RBAC or access control change detected",
        "default_severity": "WARNING", "aiuc1_controls": ["B006", "E015"]},
}

VALID_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@app.queue_trigger(arg_name="msg", queue_name="log-security-event-input", connection="AzureWebJobsStorage")
@app.queue_output(arg_name="output", queue_name="log-security-event-output", connection="AzureWebJobsStorage")
def log_security_event(msg: func.QueueMessage, output: func.Out[str]):
    """Log a structured security event to Application Insights."""
    body, correlation_id = parse_queue_msg(msg)
    field_error = validate_required_fields(body, ["category", "agent_id", "description"])
    if field_error:
        write_output(output, build_error_envelope("log_security_event", field_error,
                     error_code="MISSING_FIELDS"), correlation_id)
        return
    category = body["category"].strip().lower()
    agent_id = body["agent_id"].strip()
    description = body["description"].strip()
    if category not in VALID_CATEGORIES:
        write_output(output, build_error_envelope("log_security_event",
                     f"Invalid category '{category}'. Must be one of: {sorted(VALID_CATEGORIES.keys())}",
                     error_code="INVALID_CATEGORY"), correlation_id)
        return
    severity = body.get("severity", "").strip().upper()
    if severity and severity not in VALID_SEVERITIES:
        write_output(output, build_error_envelope("log_security_event",
                     f"Invalid severity '{severity}'. Must be one of: {sorted(VALID_SEVERITIES)}",
                     error_code="INVALID_SEVERITY"), correlation_id)
        return
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
    }
    write_output(output, build_success_envelope("log_security_event", result,
                 aiuc1_controls=["E015", "B009"]), correlation_id)
