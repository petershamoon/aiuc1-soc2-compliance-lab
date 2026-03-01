# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Terraform Root Module
# ---------------------------------------------------------------------------
# This root module orchestrates remediation of intentional misconfigurations
# deployed in the lab environment.  The agent's run_terraform_plan and
# run_terraform_apply functions operate against this directory.
#
# AIUC-1 Controls:
#   C007  Human-in-the-loop approval before apply
#   D003  Restrict unsafe tool calls (blocked resource types)
#   B006  Scope boundaries (only lab resource groups)
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }

  # State stored locally for the lab — in production, use remote backend
  # backend "azurerm" {
  #   resource_group_name  = "rg-aiuc1-foundry"
  #   storage_account_name = "aiuc1tfstate"
  #   container_name       = "tfstate"
  #   key                  = "lab.terraform.tfstate"
  # }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# ---------------------------------------------------------------------------
# Data Sources — Reference existing lab resources
# ---------------------------------------------------------------------------

data "azurerm_resource_group" "production" {
  name = var.rg_production
}

data "azurerm_resource_group" "development" {
  name = var.rg_development
}

# ---------------------------------------------------------------------------
# Module: NSG Remediation
# ---------------------------------------------------------------------------
# Fixes the intentional CC6 misconfigurations:
#   - prod-open-nsg: RDP (3389) open to *
#   - dev-open-nsg:  SSH (22) open to *

module "nsg_remediation_prod" {
  source = "./modules/nsg-remediation"

  resource_group_name = data.azurerm_resource_group.production.name
  location            = data.azurerm_resource_group.production.location
  nsg_names           = ["prod-open-nsg"]
  allowed_source_cidr = var.allowed_source_cidr
}

module "nsg_remediation_dev" {
  source = "./modules/nsg-remediation"

  resource_group_name = data.azurerm_resource_group.development.name
  location            = data.azurerm_resource_group.development.location
  nsg_names           = ["dev-open-nsg"]
  allowed_source_cidr = var.allowed_source_cidr
}

# ---------------------------------------------------------------------------
# Module: Storage Remediation
# ---------------------------------------------------------------------------
# Fixes the intentional CC5 misconfiguration:
#   - aiuc1prodstorage: public blob access enabled

module "storage_remediation" {
  source = "./modules/storage-remediation"

  resource_group_name  = data.azurerm_resource_group.production.name
  storage_account_name = var.storage_account_name
}
