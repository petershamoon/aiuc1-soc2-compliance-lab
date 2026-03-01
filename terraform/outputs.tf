# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Terraform Outputs
# ---------------------------------------------------------------------------

output "nsg_remediation_prod_summary" {
  description = "Summary of production NSG remediation actions"
  value       = module.nsg_remediation_prod.remediation_summary
}

output "nsg_remediation_dev_summary" {
  description = "Summary of development NSG remediation actions"
  value       = module.nsg_remediation_dev.remediation_summary
}

output "storage_remediation_summary" {
  description = "Summary of storage remediation actions"
  value       = module.storage_remediation.remediation_summary
}
