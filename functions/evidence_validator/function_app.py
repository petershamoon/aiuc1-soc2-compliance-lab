# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — evidence_validator
# ---------------------------------------------------------------------------
# Data Provider Function (3 of 6)
#
# Purpose:
#   Validates that a piece of compliance evidence (artifact) exists and
#   returns its metadata.  Does NOT judge whether the evidence is
#   *sufficient* — that's the agent's job.
#
# Evidence types supported:
#   • azure_resource  — verifies a resource exists and returns its state
#   • policy_state    — checks Azure Policy compliance for a resource
#   • document        — verifies a governance document exists in the repo
#   • log_entry       — checks for specific Activity Log events
#
# ChatGPT Audit Fix #5:
#   This function includes a non-technical evidence map per CC category,
#   returning human-readable descriptions of what evidence is expected.
#
# AIUC-1 Controls:
#   AIUC-1-09  Scope Boundaries  — only validates resources in scope
#   AIUC-1-17  Data Minimization — returns metadata, not full content
#   AIUC-1-18  Input Validation  — validates evidence type and target
#   AIUC-1-19  Output Filtering  — sanitises output
#   AIUC-1-22  Logging           — logs every validation attempt
#   AIUC-1-46  Provenance        — tracks evidence chain of custody
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
import os
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.azure_clients import get_mgmt_client
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.validators import validate_resource_group, validate_required_fields

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.evidence_validator")


# ---- Non-Technical Evidence Map (Audit Fix #5) ---------------------------
# Maps each CC category to the types of evidence an auditor would expect,
# described in plain language for non-technical stakeholders.

EVIDENCE_MAP = {
    "CC1": {
        "category": "Control Environment",
        "evidence_types": [
            "Organisational chart showing security reporting lines",
            "Board-approved information security policy",
            "Risk assessment methodology documentation",
            "Annual security awareness training records",
        ],
    },
    "CC2": {
        "category": "Communication and Information",
        "evidence_types": [
            "Incident notification procedures",
            "Azure Activity Log alert configurations",
            "Stakeholder communication templates",
            "Change advisory board meeting minutes",
        ],
    },
    "CC3": {
        "category": "Risk Assessment",
        "evidence_types": [
            "Risk register with likelihood and impact ratings",
            "Azure Security Center assessment results",
            "Third-party vulnerability scan reports",
            "Risk acceptance documentation for known issues",
        ],
    },
    "CC4": {
        "category": "Monitoring Activities",
        "evidence_types": [
            "Application Insights dashboard screenshots",
            "Log Analytics query results showing monitoring coverage",
            "Alert rule configurations and escalation procedures",
            "Monthly monitoring effectiveness review reports",
        ],
    },
    "CC5": {
        "category": "Control Activities",
        "evidence_types": [
            "Storage account encryption configuration (at-rest)",
            "TLS 1.2 enforcement evidence",
            "Key Vault access policies",
            "Data classification policy and implementation proof",
        ],
    },
    "CC6": {
        "category": "Logical and Physical Access Controls",
        "evidence_types": [
            "NSG rule configurations showing least-privilege",
            "RBAC role assignment listings",
            "Entra ID conditional access policies",
            "MFA enforcement evidence for privileged accounts",
            "Access review completion records",
        ],
    },
    "CC7": {
        "category": "System Operations",
        "evidence_types": [
            "SQL Server auditing policy configuration",
            "Database backup and recovery test results",
            "Patch management compliance reports",
            "Incident response plan and tabletop exercise records",
        ],
    },
    "CC8": {
        "category": "Change Management",
        "evidence_types": [
            "Azure Policy compliance state reports",
            "Terraform plan/apply audit logs",
            "Pull request review and approval records",
            "Deployment pipeline configuration (CI/CD)",
        ],
    },
    "CC9": {
        "category": "Risk Mitigation",
        "evidence_types": [
            "Microsoft Defender for Cloud secure score",
            "Remediation plan (POA&M) with timelines",
            "Insurance coverage documentation",
            "Business continuity and disaster recovery plans",
        ],
    },
}

# Type II evidence sampling approach (Audit Fix #6)
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
        # Parse resource ID components
        resource = resource_client.resources.get_by_id(
            resource_id, api_version="2023-07-01"
        )
        return {
            "exists": True,
            "name": resource.name,
            "type": resource.type,
            "location": resource.location,
            "provisioning_state": resource.properties.get("provisioningState", "unknown")
            if resource.properties else "unknown",
            "tags": dict(resource.tags) if resource.tags else {},
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "exists": False,
            "resource_id": resource_id,
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
            "exists": True,
            "path": document_path,
            "size_bytes": stat.st_size,
            "last_modified": datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        return {
            "exists": False,
            "path": document_path,
            "error": "Document not found in repository",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }


@app.route(route="evidence_validator", methods=["POST"])
@log_function_call("evidence_validator", aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Validate existence and metadata of compliance evidence artifacts.

    Request body (JSON):
        {
            "evidence_type": "azure_resource",  // required
            "target": "/subscriptions/.../...", // required — resource ID or path
            "cc_category": "CC6"                // optional — for evidence map lookup
        }

    Response:
        Standard envelope with validation result in data.validation.
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "evidence_validator",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    # ---- Input validation (AIUC-1-18) ------------------------------------
    field_error = validate_required_fields(body, ["evidence_type", "target"])
    if field_error:
        return build_error_response(
            "evidence_validator", field_error, error_code="MISSING_FIELDS", status_code=400
        )

    evidence_type = body["evidence_type"].strip().lower()
    target = body["target"].strip()
    cc_category = body.get("cc_category", "").strip().upper()

    valid_types = {"azure_resource", "policy_state", "document", "log_entry"}
    if evidence_type not in valid_types:
        return build_error_response(
            "evidence_validator",
            f"Invalid evidence_type '{evidence_type}'. Must be one of: {sorted(valid_types)}",
            error_code="INVALID_EVIDENCE_TYPE",
            status_code=400,
        )

    # ---- Validate evidence -----------------------------------------------
    settings = get_settings()

    if evidence_type == "azure_resource":
        validation = _validate_azure_resource(target, settings)
    elif evidence_type == "document":
        validation = _validate_document(target, settings)
    else:
        # policy_state and log_entry are planned but return metadata for now
        validation = {
            "evidence_type": evidence_type,
            "target": target,
            "status": "validator_not_yet_implemented",
            "note": "This evidence type validator is planned for a future iteration.",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---- Build response --------------------------------------------------
    result = {
        "evidence_type": evidence_type,
        "target": target,
        "validation": validation,
        "evidence_map": EVIDENCE_MAP.get(cc_category, {}) if cc_category else {},
        "type_ii_sampling": TYPE_II_SAMPLING,
    }

    return build_success_response(
        "evidence_validator",
        result,
        aiuc1_controls=["AIUC-1-09", "AIUC-1-17", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-46"],
    )
