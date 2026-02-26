# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Azure SDK Client Factory
# ---------------------------------------------------------------------------
# Provides authenticated Azure SDK clients for the management-plane APIs
# that the GRC tool functions call.
#
# Authentication strategy:
#   1. In production (Function App) → Managed Identity via DefaultAzureCredential
#   2. Locally → Service Principal env vars (AZURE_CLIENT_ID / SECRET / TENANT)
#
# AIUC-1 Controls:
#   A004  Credential Management — uses DefaultAzureCredential chain
#   B006  Scope Boundaries     — subscription ID is explicit
#   E015  Logging              — client creation is logged
# ---------------------------------------------------------------------------

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.policyinsights import PolicyInsightsClient

from .config import get_settings

logger = logging.getLogger("aiuc1.azure_clients")

# ---- Credential -----------------------------------------------------------

@lru_cache(maxsize=1)
def get_credential() -> DefaultAzureCredential:
    """Return a cached DefaultAzureCredential.

    DefaultAzureCredential tries, in order:
      1. EnvironmentCredential  (service principal — local dev)
      2. ManagedIdentityCredential  (Function App production)
      3. AzureCliCredential  (developer workstation)

    Caching avoids repeated token negotiations on warm invocations.
    """
    logger.info("Initialising DefaultAzureCredential")
    return DefaultAzureCredential()


# ---- Management Clients ---------------------------------------------------

# Map of friendly names → (SDK class, extra kwargs builder)
# This lets get_mgmt_client() act as a simple factory.
_CLIENT_REGISTRY: dict[str, type] = {
    "resource": ResourceManagementClient,
    "network": NetworkManagementClient,
    "storage": StorageManagementClient,
    "sql": SqlManagementClient,
    "security": SecurityCenter,
    "authorization": AuthorizationManagementClient,
    "policy_insights": PolicyInsightsClient,
}


def get_mgmt_client(service: str, **kwargs: Any) -> Any:
    """Factory that returns an authenticated Azure management client.

    Args:
        service: One of the keys in _CLIENT_REGISTRY (e.g. "network").
        **kwargs: Extra keyword arguments forwarded to the SDK constructor.

    Returns:
        An authenticated management client for the requested service.

    Raises:
        ValueError: If *service* is not in the registry.

    Example::

        network_client = get_mgmt_client("network")
        nsgs = network_client.network_security_groups.list_all()
    """
    if service not in _CLIENT_REGISTRY:
        raise ValueError(
            f"Unknown service '{service}'. "
            f"Available: {sorted(_CLIENT_REGISTRY.keys())}"
        )

    settings = get_settings()
    credential = get_credential()
    client_cls = _CLIENT_REGISTRY[service]

    # SecurityCenter uses asc_location instead of subscription_id as first
    # positional arg in some SDK versions — handle that quirk.
    if service == "security":
        client = client_cls(
            credential=credential,
            subscription_id=settings.azure_subscription_id,
            asc_location="eastus2",
            **kwargs,
        )
    else:
        client = client_cls(
            credential=credential,
            subscription_id=settings.azure_subscription_id,
            **kwargs,
        )

    logger.info("Created %s client for subscription %s", service, "***-redacted")
    return client
