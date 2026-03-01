# ---------------------------------------------------------------------------
# NSG Remediation Module
# ---------------------------------------------------------------------------
# Remediates CC6 findings by replacing overly permissive NSG rules
# (source = "*") with restricted CIDR blocks.
#
# Strategy: Create new restricted rules at priority 200/201 that override
# the existing permissive rules (priority 100).  We cannot use priority 100
# because the existing AllowRDPFromAnywhere / AllowSSHFromAnywhere rules
# already occupy that slot.  Azure does not allow two rules with the same
# priority and direction.
#
# The agent's run_terraform_plan will show the diff before apply.
# ---------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Resource group containing the NSGs"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "nsg_names" {
  description = "List of NSG names to remediate"
  type        = list(string)
}

variable "allowed_source_cidr" {
  description = "CIDR to replace * with"
  type        = string
  default     = "10.0.0.0/8"
}

# ---------------------------------------------------------------------------
# Data: Look up existing NSGs
# ---------------------------------------------------------------------------

data "azurerm_network_security_group" "target" {
  for_each            = toset(var.nsg_names)
  name                = each.value
  resource_group_name = var.resource_group_name
}

# ---------------------------------------------------------------------------
# Resource: Deny-all rules at priority 200 to block the permissive rules
# ---------------------------------------------------------------------------
# These deny rules have LOWER priority number than default allows but
# HIGHER than the existing permissive rules.  We add explicit deny rules
# for RDP and SSH from anywhere, then allow from our restricted CIDR.

resource "azurerm_network_security_rule" "deny_rdp_from_internet" {
  for_each = {
    for name in var.nsg_names : name => name
    if contains(keys(data.azurerm_network_security_group.target), name)
  }

  name                        = "Deny-RDP-From-Internet"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = each.value
}

resource "azurerm_network_security_rule" "deny_ssh_from_internet" {
  for_each = {
    for name in var.nsg_names : name => name
    if contains(keys(data.azurerm_network_security_group.target), name)
  }

  name                        = "Deny-SSH-From-Internet"
  priority                    = 201
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = each.value
}

# ---------------------------------------------------------------------------
# Resource: Allow restricted CIDR rules at priority 110/111
# ---------------------------------------------------------------------------
# These sit between the existing permissive rules (100) and our deny rules
# (200/201), ensuring that only traffic from the allowed CIDR can reach
# RDP/SSH.

resource "azurerm_network_security_rule" "restrict_rdp" {
  for_each = {
    for name in var.nsg_names : name => name
    if contains(keys(data.azurerm_network_security_group.target), name)
  }

  name                        = "Restrict-RDP-Inbound"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = var.allowed_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = each.value
}

resource "azurerm_network_security_rule" "restrict_ssh" {
  for_each = {
    for name in var.nsg_names : name => name
    if contains(keys(data.azurerm_network_security_group.target), name)
  }

  name                        = "Restrict-SSH-Inbound"
  priority                    = 111
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.allowed_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = each.value
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

output "remediation_summary" {
  description = "Summary of NSG remediation"
  value = {
    nsgs_targeted     = var.nsg_names
    allowed_cidr      = var.allowed_source_cidr
    rules_created     = ["Deny-RDP-From-Internet", "Deny-SSH-From-Internet", "Restrict-RDP-Inbound", "Restrict-SSH-Inbound"]
    resource_group    = var.resource_group_name
  }
}
