# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Configuration Management
# ---------------------------------------------------------------------------
# Centralised settings loaded from environment variables.  No secrets are
# ever hardcoded — this satisfies:
#   AIUC-1-34  Credential Management
#   AIUC-1-35  Secrets Rotation
#
# In production the Function App's Application Settings populate these
# env vars automatically.  Locally, developers copy .env.example → .env
# and fill in real values.
# ---------------------------------------------------------------------------

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional


@dataclass(frozen=True)
class Settings:
    """Immutable application settings sourced from environment variables.

    Frozen dataclass prevents accidental mutation after initialisation.
    Every field maps to an env var documented in .env.example.
    """

    # --- Azure Identity ---------------------------------------------------
    azure_client_id: str = field(default="")
    azure_client_secret: str = field(default="")
    azure_tenant_id: str = field(default="")
    azure_subscription_id: str = field(default="")

    # --- Azure AI Foundry -------------------------------------------------
    foundry_endpoint: str = field(default="")
    foundry_api_key: str = field(default="")

    # --- OpenAI (model inference) -----------------------------------------
    openai_api_key: str = field(default="")

    # --- SQL Server -------------------------------------------------------
    sql_admin_password: str = field(default="")

    # --- Resource Groups --------------------------------------------------
    rg_foundry: str = field(default="rg-aiuc1-foundry")
    rg_production: str = field(default="rg-production")
    rg_development: str = field(default="rg-development")

    # --- Foundry Names ----------------------------------------------------
    foundry_hub_name: str = field(default="")
    foundry_project_name: str = field(default="")

    # --- Application Insights ---------------------------------------------
    appinsights_connection_string: str = field(default="")

    # --- Git / Repo -------------------------------------------------------
    git_repo_path: str = field(default="/home/ubuntu/aiuc1-soc2-compliance-lab")

    # --- Terraform --------------------------------------------------------
    terraform_working_dir: str = field(default="")

    @property
    def allowed_resource_groups(self) -> list[str]:
        """Resource groups the functions are allowed to query/modify.

        AIUC-1-09 (Scope Boundaries): agents must not access resources
        outside the defined lab scope.
        """
        return [self.rg_foundry, self.rg_production, self.rg_development]


def _env(key: str, default: str = "") -> str:
    """Read an environment variable with a fallback default.

    We deliberately do NOT raise on missing vars so that local development
    and unit tests can run with partial configuration.
    """
    return os.environ.get(key, default)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build and cache a Settings instance from the current environment.

    The @lru_cache decorator ensures we only read env vars once per
    process lifetime, which is the recommended pattern for Azure
    Functions running on the Consumption plan (cold-start optimisation).
    """
    return Settings(
        azure_client_id=_env("AZURE_CLIENT_ID"),
        azure_client_secret=_env("AZURE_CLIENT_SECRET"),
        azure_tenant_id=_env("AZURE_TENANT_ID"),
        azure_subscription_id=_env("AZURE_SUBSCRIPTION_ID"),
        foundry_endpoint=_env("AZURE_FOUNDRY_ENDPOINT"),
        foundry_api_key=_env("AZURE_FOUNDRY_API_KEY"),
        openai_api_key=_env("OPENAI_API_KEY"),
        sql_admin_password=_env("SQL_ADMIN_PASSWORD"),
        rg_foundry=_env("RESOURCE_GROUP_FOUNDRY", "rg-aiuc1-foundry"),
        rg_production=_env("RESOURCE_GROUP_PRODUCTION", "rg-production"),
        rg_development=_env("RESOURCE_GROUP_DEVELOPMENT", "rg-development"),
        foundry_hub_name=_env("FOUNDRY_HUB_NAME"),
        foundry_project_name=_env("FOUNDRY_PROJECT_NAME"),
        appinsights_connection_string=_env("APPINSIGHTS_CONNECTION_STRING"),
        git_repo_path=_env("GIT_REPO_PATH", "/home/ubuntu/aiuc1-soc2-compliance-lab"),
        terraform_working_dir=_env("TERRAFORM_WORKING_DIR", ""),
    )
