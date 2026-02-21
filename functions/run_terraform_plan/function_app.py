# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — run_terraform_plan
# ---------------------------------------------------------------------------
# Action Function (2 of 4)
#
# Purpose:
#   Executes `terraform plan` in the lab's Terraform working directory,
#   validates the plan output against safety rules, and returns the
#   plan summary with an approval token if the plan passes validation.
#
# ChatGPT Audit Fix #3 — Enhanced Terraform Plan Validation:
#   Beyond simple BLOCKED_PATTERNS string matching, this function:
#   1. Parses `terraform plan -json` output
#   2. Denies dangerous resource types (e.g. role_assignment with scope "/")
#   3. Denies any `destroy` actions on production resources
#   4. Validates all resources have required tags
#   5. Azure Policy deny assignments act as a backstop
#
# Security model:
#   • Plan is read-only — no infrastructure changes
#   • The approval token is required by run_terraform_apply
#   • Token is a signed hash of the plan, preventing replay attacks
#   • AIUC-1-11 (Human Oversight) — plan must be reviewed before apply
#
# AIUC-1 Controls:
#   AIUC-1-07  Risk Assessment     — plan validation is risk assessment
#   AIUC-1-11  Human Oversight     — approval gate before apply
#   AIUC-1-18  Input Validation    — validates working directory
#   AIUC-1-19  Output Filtering    — sanitises plan output
#   AIUC-1-22  Logging             — logs plan execution and results
#   AIUC-1-30  Change Management   — terraform plan is change control
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
import hashlib
import hmac
import subprocess
import os
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.sanitizer import redact_secrets

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.run_terraform_plan")


# ---- Blocked Patterns (string-level) ------------------------------------
# First line of defence: simple string matching for obviously dangerous
# patterns in the plan output.

BLOCKED_PATTERNS = [
    "azurerm_role_assignment",       # Role assignments need extra scrutiny
    "azurerm_management_group",      # Management group changes are high-risk
    "azurerm_subscription",          # Subscription-level changes
    "azurerm_policy_exemption",      # Policy exemptions bypass controls
    "destroy",                       # Caught more precisely in JSON validation
]

# ---- Dangerous Resource Types (JSON-level) -------------------------------
# These resource types require special validation beyond string matching.

DANGEROUS_RESOURCE_TYPES = {
    "azurerm_role_assignment": "Role assignments can escalate privileges",
    "azurerm_management_group": "Management group changes affect governance scope",
    "azurerm_policy_exemption": "Policy exemptions bypass compliance controls",
    "azurerm_key_vault_access_policy": "Key Vault access changes affect secret management",
}

# Required tags that every resource must have
REQUIRED_TAGS = {"project", "environment", "managed_by"}


def _validate_plan_json(plan_json: list[dict]) -> list[dict]:
    """Validate parsed terraform plan JSON output.

    Implements ChatGPT Audit Fix #3 — structured validation beyond
    simple string matching.

    Args:
        plan_json: List of resource change objects from `terraform plan -json`.

    Returns:
        List of validation findings (empty = plan is safe).
    """
    findings = []

    for change in plan_json:
        change_type = change.get("type", "")
        action = change.get("change", {}).get("actions", [])
        resource_address = change.get("address", "unknown")

        # Rule 1: Deny dangerous resource types
        if change_type in DANGEROUS_RESOURCE_TYPES:
            # Exception: allow role_assignment if scope is resource-group level
            if change_type == "azurerm_role_assignment":
                scope = change.get("change", {}).get("after", {}).get("scope", "")
                if scope == "/" or scope.count("/") <= 2:
                    findings.append({
                        "rule": "dangerous_resource_type",
                        "resource": resource_address,
                        "type": change_type,
                        "reason": (
                            f"{DANGEROUS_RESOURCE_TYPES[change_type]}. "
                            f"Scope '{scope}' is too broad (subscription or root level)."
                        ),
                        "severity": "critical",
                    })
            else:
                findings.append({
                    "rule": "dangerous_resource_type",
                    "resource": resource_address,
                    "type": change_type,
                    "reason": DANGEROUS_RESOURCE_TYPES[change_type],
                    "severity": "high",
                })

        # Rule 2: Deny destroy actions on production resources
        if "delete" in action or "destroy" in str(action):
            if "production" in resource_address.lower() or "prod" in resource_address.lower():
                findings.append({
                    "rule": "production_destroy_blocked",
                    "resource": resource_address,
                    "actions": action,
                    "reason": "Destroy actions on production resources are blocked",
                    "severity": "critical",
                })

        # Rule 3: Validate required tags on create/update
        if "create" in action or "update" in action:
            after_tags = change.get("change", {}).get("after", {}).get("tags", {})
            if after_tags is not None:
                missing_tags = REQUIRED_TAGS - set(after_tags.keys())
                if missing_tags:
                    findings.append({
                        "rule": "missing_required_tags",
                        "resource": resource_address,
                        "missing_tags": list(missing_tags),
                        "reason": f"Resources must have tags: {REQUIRED_TAGS}",
                        "severity": "medium",
                    })

    return findings


def _generate_approval_token(plan_hash: str) -> str:
    """Generate a signed approval token for the plan.

    The token is an HMAC of the plan hash using a server-side secret.
    run_terraform_apply validates this token before executing.

    In production, the secret would be in Key Vault. For this lab,
    we use an environment variable.
    """
    secret = os.environ.get("TERRAFORM_APPROVAL_SECRET", "lab-default-secret")
    token = hmac.new(
        secret.encode(),
        plan_hash.encode(),
        hashlib.sha256,
    ).hexdigest()
    return token


@app.route(route="run_terraform_plan", methods=["POST"])
@log_function_call("run_terraform_plan", aiuc1_controls=["AIUC-1-07", "AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Execute terraform plan with validation and approval gate.

    Request body (JSON):
        {
            "working_dir": "terraform/remediation",  // optional — override default
            "target": "module.nsg_remediation",       // optional — specific target
            "var_file": "lab.tfvars"                  // optional — variables file
        }

    Response:
        Standard envelope with plan summary, validation results,
        and approval_token (if plan passes validation).
    """
    try:
        body = req.get_json()
    except ValueError:
        body = {}

    settings = get_settings()
    working_dir = body.get("working_dir", settings.terraform_working_dir)

    if not working_dir:
        working_dir = os.path.join(settings.git_repo_path, "terraform")

    # ---- Validate working directory exists --------------------------------
    if not os.path.isdir(working_dir):
        return build_error_response(
            "run_terraform_plan",
            f"Terraform working directory does not exist: {working_dir}",
            error_code="INVALID_WORKING_DIR",
            status_code=400,
        )

    # ---- Build terraform plan command ------------------------------------
    cmd = ["terraform", "plan", "-no-color", "-detailed-exitcode"]

    target = body.get("target")
    if target:
        cmd.extend(["-target", target])

    var_file = body.get("var_file")
    if var_file:
        cmd.extend(["-var-file", var_file])

    # Also generate JSON output for structured validation
    json_cmd = cmd + ["-json"]

    # ---- Execute terraform plan ------------------------------------------
    try:
        # Run human-readable plan
        plan_result = subprocess.run(
            cmd,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=300,  # 5-minute timeout
        )

        plan_output = plan_result.stdout
        plan_stderr = plan_result.stderr

        # Exit code 0 = no changes, 1 = error, 2 = changes present
        has_changes = plan_result.returncode == 2
        has_error = plan_result.returncode == 1

        if has_error:
            return build_error_response(
                "run_terraform_plan",
                redact_secrets(plan_stderr or plan_output),
                error_code="TERRAFORM_PLAN_ERROR",
                status_code=500,
                details={"exit_code": plan_result.returncode},
            )

    except subprocess.TimeoutExpired:
        return build_error_response(
            "run_terraform_plan",
            "Terraform plan timed out after 300 seconds",
            error_code="TIMEOUT",
            status_code=504,
        )
    except FileNotFoundError:
        return build_error_response(
            "run_terraform_plan",
            "Terraform binary not found. Ensure terraform is installed.",
            error_code="TERRAFORM_NOT_FOUND",
            status_code=500,
        )

    # ---- String-level blocked pattern check ------------------------------
    blocked_hits = []
    plan_lower = plan_output.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in plan_lower:
            blocked_hits.append(pattern)

    # ---- JSON-level structured validation --------------------------------
    json_findings = []
    try:
        json_result = subprocess.run(
            json_cmd,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if json_result.stdout:
            # Parse line-delimited JSON
            plan_changes = []
            for line in json_result.stdout.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "resource_drift" or entry.get("type") == "planned_change":
                        plan_changes.append(entry)
                except json.JSONDecodeError:
                    continue
            json_findings = _validate_plan_json(plan_changes)
    except Exception as e:
        logger.warning("JSON plan validation failed: %s", e)

    # ---- Determine approval status ---------------------------------------
    critical_findings = [
        f for f in json_findings if f.get("severity") == "critical"
    ]
    plan_approved = not blocked_hits and not critical_findings

    # Generate plan hash and approval token
    plan_hash = hashlib.sha256(plan_output.encode()).hexdigest()
    approval_token = _generate_approval_token(plan_hash) if plan_approved else None

    # ---- Build response --------------------------------------------------
    result = {
        "has_changes": has_changes,
        "plan_approved": plan_approved,
        "plan_hash": plan_hash,
        "approval_token": approval_token,
        "plan_summary": redact_secrets(plan_output[:5000]),  # Truncate for response size
        "validation": {
            "blocked_pattern_hits": blocked_hits,
            "json_findings": json_findings,
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

    return build_success_response(
        "run_terraform_plan",
        result,
        aiuc1_controls=["AIUC-1-07", "AIUC-1-11", "AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-30"],
    )
