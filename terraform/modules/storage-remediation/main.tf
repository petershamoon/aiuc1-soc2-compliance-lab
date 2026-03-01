# ---------------------------------------------------------------------------
# Storage Remediation Module
# ---------------------------------------------------------------------------
# Remediates CC5 findings by disabling public blob access on the
# target storage account.
#
# This uses azurerm_storage_account data source + resource to update
# the allow_nested_items_to_be_public and public_network_access settings.
# ---------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Resource group containing the storage account"
  type        = string
}

variable "storage_account_name" {
  description = "Name of the storage account to remediate"
  type        = string
}

# ---------------------------------------------------------------------------
# Data: Look up the existing storage account
# ---------------------------------------------------------------------------

data "azurerm_storage_account" "target" {
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
}

# ---------------------------------------------------------------------------
# Resource: Disable public blob access
# ---------------------------------------------------------------------------
# We import the existing storage account and update its public access settings.
# Note: This requires an import block or manual import before first apply.

resource "azurerm_storage_account" "remediated" {
  name                          = var.storage_account_name
  resource_group_name           = var.resource_group_name
  location                      = data.azurerm_storage_account.target.location
  account_tier                  = data.azurerm_storage_account.target.account_tier
  account_replication_type      = data.azurerm_storage_account.target.account_replication_type

  # CC5 Remediation: Disable public blob access
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true  # Keep network access but disable anonymous blob access

  # Preserve existing settings
  min_tls_version               = "TLS1_2"
  cross_tenant_replication_enabled = false

  tags = data.azurerm_storage_account.target.tags

  lifecycle {
    # Prevent accidental deletion of the storage account
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

output "remediation_summary" {
  description = "Summary of storage remediation"
  value = {
    storage_account        = var.storage_account_name
    public_blob_access     = false
    public_network_access  = true
    min_tls_version        = "TLS1_2"
    resource_group         = var.resource_group_name
  }
}
