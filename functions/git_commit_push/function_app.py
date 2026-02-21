# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — git_commit_push
# ---------------------------------------------------------------------------
# Action Function (4 of 4)
#
# Purpose:
#   Commits compliance artifacts (reports, POA&M entries, evidence) to
#   the Git repository and pushes to the remote.  This creates an
#   immutable audit trail of all compliance activities.
#
# Security considerations:
#   • Pre-commit hook: scans staged files for secrets before committing
#   • Only allows commits to specific directories (reports/, docs/, terraform/)
#   • Commit messages must follow conventional commit format
#   • The function refuses to commit files matching .gitignore patterns
#
# AIUC-1 Controls:
#   AIUC-1-18  Input Validation    — validates file paths and commit message
#   AIUC-1-19  Output Filtering    — scans for secrets before commit
#   AIUC-1-22  Logging             — logs every commit operation
#   AIUC-1-23  Audit Trail         — git history IS the audit trail
#   AIUC-1-30  Change Management   — commits are tracked changes
#   AIUC-1-34  Credential Mgmt    — pre-commit secret scanning
# ---------------------------------------------------------------------------

import azure.functions as func
import logging
import json
import subprocess
import os
import re
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import get_settings
from shared.logger import log_event, log_function_call
from shared.response import build_success_response, build_error_response
from shared.sanitizer import redact_secrets
from shared.validators import validate_required_fields

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger("aiuc1.git_commit_push")


# ---- Allowed commit directories ------------------------------------------
# Only these top-level directories can be committed to via this function.
# This prevents agents from modifying function code or CI/CD config.

ALLOWED_DIRECTORIES = {
    "reports",
    "docs",
    "terraform",
    "policies",
    "evidence",
}

# ---- Conventional commit pattern -----------------------------------------
# Commit messages must follow: type(scope): description
# e.g., "feat(evidence): add CC6 NSG assessment report"

COMMIT_MESSAGE_PATTERN = re.compile(
    r"^(feat|fix|docs|chore|refactor|test|ci)\([a-z0-9-]+\): .{10,200}$"
)

# ---- Secret patterns for pre-commit scanning -----------------------------
SECRET_PATTERNS = [
    re.compile(r"(?:password|secret|key|token)\s*[=:]\s*['\"][^'\"]{8,}", re.IGNORECASE),
    re.compile(r"DefaultEndpointsProtocol=", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # Base64 keys
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI keys
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
]


def _scan_for_secrets(file_path: str) -> list[str]:
    """Scan a file for potential secrets before committing.

    Returns a list of warning messages if secrets are detected.
    """
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
    """Validate that all file paths are within allowed directories.

    Returns (valid_files, rejected_files).
    """
    valid = []
    rejected = []

    for file_path in files:
        # Normalise and check it's within the repo
        normalised = os.path.normpath(file_path)
        if normalised.startswith("/"):
            # Absolute path — check it's within repo
            if not normalised.startswith(repo_path):
                rejected.append(f"{file_path} (outside repository)")
                continue
            relative = os.path.relpath(normalised, repo_path)
        else:
            relative = normalised

        # Check top-level directory is allowed
        top_dir = relative.split(os.sep)[0]
        if top_dir not in ALLOWED_DIRECTORIES:
            rejected.append(f"{file_path} (directory '{top_dir}' not in allowed list)")
            continue

        valid.append(relative)

    return valid, rejected


@app.route(route="git_commit_push", methods=["POST"])
@log_function_call("git_commit_push", aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-23", "AIUC-1-30", "AIUC-1-34"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Commit and push compliance artifacts to the Git repository.

    Request body (JSON):
        {
            "files": ["reports/cc6-assessment.md"],  // required — files to commit
            "message": "feat(evidence): add CC6 NSG assessment report",  // required
            "agent_id": "evidence-collector",  // optional — for audit trail
            "push": true                       // optional — push after commit (default true)
        }

    Response:
        Standard envelope with commit hash and push status.
    """
    try:
        body = req.get_json()
    except ValueError:
        return build_error_response(
            "git_commit_push",
            "Request body must be valid JSON",
            error_code="INVALID_JSON",
            status_code=400,
        )

    # ---- Input validation (AIUC-1-18) ------------------------------------
    field_error = validate_required_fields(body, ["files", "message"])
    if field_error:
        return build_error_response(
            "git_commit_push", field_error, error_code="MISSING_FIELDS", status_code=400
        )

    files = body["files"]
    message = body["message"].strip()
    agent_id = body.get("agent_id", "unknown")
    should_push = body.get("push", True)

    if not isinstance(files, list) or not files:
        return build_error_response(
            "git_commit_push",
            "files must be a non-empty list of file paths",
            error_code="INVALID_FILES",
            status_code=400,
        )

    # Validate commit message format
    if not COMMIT_MESSAGE_PATTERN.match(message):
        return build_error_response(
            "git_commit_push",
            f"Commit message must follow conventional format: "
            f"type(scope): description (10-200 chars). Got: '{message}'",
            error_code="INVALID_COMMIT_MESSAGE",
            status_code=400,
        )

    # ---- Validate file paths ---------------------------------------------
    settings = get_settings()
    repo_path = settings.git_repo_path

    valid_files, rejected_files = _validate_file_paths(files, repo_path)

    if rejected_files:
        return build_error_response(
            "git_commit_push",
            f"Some files are outside allowed directories: {rejected_files}",
            error_code="PATH_VIOLATION",
            status_code=403,
            details={"rejected": rejected_files, "allowed_dirs": list(ALLOWED_DIRECTORIES)},
        )

    if not valid_files:
        return build_error_response(
            "git_commit_push",
            "No valid files to commit after path validation",
            error_code="NO_VALID_FILES",
            status_code=400,
        )

    # ---- Pre-commit secret scanning (AIUC-1-34) --------------------------
    all_warnings = []
    for file_path in valid_files:
        full_path = os.path.join(repo_path, file_path)
        if os.path.isfile(full_path):
            warnings = _scan_for_secrets(full_path)
            all_warnings.extend(warnings)

    if all_warnings:
        log_event(
            "security_event",
            function_name="git_commit_push",
            agent_id=agent_id,
            severity="WARNING",
            details={"secret_scan_warnings": all_warnings},
            aiuc1_controls=["AIUC-1-34"],
        )
        return build_error_response(
            "git_commit_push",
            "Pre-commit secret scan detected potential secrets. "
            "Review and sanitise files before committing.",
            error_code="SECRET_DETECTED",
            status_code=403,
            details={"warnings": all_warnings},
        )

    # ---- Git operations --------------------------------------------------
    try:
        # Stage files
        for file_path in valid_files:
            subprocess.run(
                ["git", "add", file_path],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
            )

        # Commit
        commit_result = subprocess.run(
            ["git", "commit", "-m", message, "--author", f"AIUC-1 Agent <{agent_id}@aiuc1.lab>"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

        if commit_result.returncode != 0:
            return build_error_response(
                "git_commit_push",
                redact_secrets(commit_result.stderr or commit_result.stdout),
                error_code="GIT_COMMIT_ERROR",
                status_code=500,
            )

        # Get commit hash
        hash_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        commit_hash = hash_result.stdout.strip()

        # Push if requested
        push_status = "skipped"
        if should_push:
            push_result = subprocess.run(
                ["git", "push"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            push_status = "success" if push_result.returncode == 0 else "failed"

    except subprocess.TimeoutExpired:
        return build_error_response(
            "git_commit_push",
            "Git push timed out after 60 seconds",
            error_code="TIMEOUT",
            status_code=504,
        )
    except Exception as e:
        return build_error_response(
            "git_commit_push",
            str(e),
            error_code="GIT_ERROR",
            status_code=500,
        )

    # ---- Build response --------------------------------------------------
    result = {
        "commit_hash": commit_hash,
        "message": message,
        "files_committed": valid_files,
        "push_status": push_status,
        "committed_by_agent": agent_id,
        "committed_at": datetime.now(timezone.utc).isoformat(),
        "audit_note": (
            "This commit was created by an AI agent via the git_commit_push "
            "function. Pre-commit secret scanning was performed. The commit "
            "is part of the immutable audit trail (AIUC-1-23)."
        ),
    }

    return build_success_response(
        "git_commit_push",
        result,
        aiuc1_controls=["AIUC-1-18", "AIUC-1-19", "AIUC-1-22", "AIUC-1-23", "AIUC-1-30", "AIUC-1-34"],
    )
