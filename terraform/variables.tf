# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Terraform Variables
# ---------------------------------------------------------------------------

variable "subscription_id" {
  description = "Azure subscription ID for the lab environment"
  type        = string
  sensitive   = true
}

variable "rg_production" {
  description = "Production resource group name"
  type        = string
  default     = "rg-production"
}

variable "rg_development" {
  description = "Development resource group name"
  type        = string
  default     = "rg-development"
}

variable "nsg_names" {
  description = "List of NSG names to remediate"
  type        = list(string)
  default     = ["prod-open-nsg", "dev-open-nsg"]
}

variable "allowed_source_cidr" {
  description = "CIDR block to restrict SSH/RDP access to (replaces 0.0.0.0/0)"
  type        = string
  default     = "10.0.0.0/8"
}

variable "storage_account_name" {
  description = "Storage account name to remediate (disable public access)"
  type        = string
  default     = "aiuc1prodstorage"
}
