#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Deployment Validation
# ---------------------------------------------------------------------------
# Pre-flight check that verifies all Azure resources are correctly wired
# before running live tests.  Run this before handing off to the test agent.
#
# Usage:
#   chmod +x scripts/validate_deployment.sh
#   ./scripts/validate_deployment.sh
# ---------------------------------------------------------------------------

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check_pass() { echo -e "  ${GREEN}✓ PASS${NC}  $*"; PASS=$((PASS+1)); }
check_fail() { echo -e "  ${RED}✗ FAIL${NC}  $*"; FAIL=$((FAIL+1)); }
check_warn() { echo -e "  ${YELLOW}⚠ WARN${NC}  $*"; WARN=$((WARN+1)); }

SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
RESOURCE_GROUP="${RESOURCE_GROUP_FOUNDRY:-rg-aiuc1-foundry}"
FUNCTION_APP_NAME="${FUNCTION_APP_NAME:-aiuc1-soc2-tools}"
STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-<REDACTED-STORAGE>}"

echo ""
echo "=========================================="
echo "AIUC-1 Deployment Validation"
echo "=========================================="
echo "Subscription: $SUBSCRIPTION_ID"
echo "Resource Group: $RESOURCE_GROUP"
echo ""

# ---------------------------------------------------------------------------
# 1. Azure CLI
# ---------------------------------------------------------------------------
echo "--- Azure CLI ---"
if command -v az &>/dev/null; then
    check_pass "Azure CLI installed ($(az version --query '\"azure-cli\"' -o tsv 2>/dev/null))"
else
    check_fail "Azure CLI not installed"
fi

CURRENT_SUB=$(az account show --query id -o tsv 2>/dev/null || echo "")
if [[ "$CURRENT_SUB" == "$SUBSCRIPTION_ID" ]]; then
    check_pass "Correct subscription active"
else
    check_fail "Wrong subscription active: $CURRENT_SUB"
fi

# ---------------------------------------------------------------------------
# 2. Resource Groups
# ---------------------------------------------------------------------------
echo ""
echo "--- Resource Groups ---"
for RG in "rg-aiuc1-foundry" "rg-production" "rg-development"; do
    if az group show --name "$RG" --output none 2>/dev/null; then
        check_pass "Resource group exists: $RG"
    else
        check_fail "Resource group missing: $RG"
    fi
done

# ---------------------------------------------------------------------------
# 3. Function App
# ---------------------------------------------------------------------------
echo ""
echo "--- Function App ---"
FA_STATUS=$(az functionapp show --name "$FUNCTION_APP_NAME" --resource-group "$RESOURCE_GROUP" --query state -o tsv 2>/dev/null || echo "NOT_FOUND")
if [[ "$FA_STATUS" == "Running" ]]; then
    check_pass "Function App running: $FUNCTION_APP_NAME"
else
    check_fail "Function App status: $FA_STATUS"
fi

# Check Python version
FA_PYTHON=$(az functionapp config show --name "$FUNCTION_APP_NAME" --resource-group "$RESOURCE_GROUP" --query linuxFxVersion -o tsv 2>/dev/null || echo "")
if [[ "$FA_PYTHON" == *"3.11"* ]]; then
    check_pass "Python 3.11 configured"
else
    check_warn "Python version: $FA_PYTHON (expected 3.11)"
fi

# Check managed identity
FA_MI=$(az functionapp identity show --name "$FUNCTION_APP_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv 2>/dev/null || echo "")
if [[ -n "$FA_MI" ]]; then
    check_pass "Managed Identity enabled: ${FA_MI:0:8}..."
else
    check_fail "Managed Identity not enabled"
fi

# ---------------------------------------------------------------------------
# 4. Storage Queues
# ---------------------------------------------------------------------------
echo ""
echo "--- Storage Queues ---"
STORAGE_KEY=$(az storage account keys list --account-name "$STORAGE_ACCOUNT_NAME" --resource-group "$RESOURCE_GROUP" --query '[0].value' -o tsv 2>/dev/null || echo "")

if [[ -z "$STORAGE_KEY" ]]; then
    check_fail "Cannot access storage account: $STORAGE_ACCOUNT_NAME"
else
    QUEUE_COUNT=$(az storage queue list --account-name "$STORAGE_ACCOUNT_NAME" --account-key "$STORAGE_KEY" --query "length(@)" -o tsv 2>/dev/null || echo "0")
    if [[ "$QUEUE_COUNT" -ge 24 ]]; then
        check_pass "Storage queues: $QUEUE_COUNT (expected ≥24)"
    else
        check_fail "Storage queues: $QUEUE_COUNT (expected ≥24)"
    fi

    # Spot-check a few queues
    for Q in "gap-analyzer-input" "gap-analyzer-output" "log-security-event-input" "log-security-event-output"; do
        EXISTS=$(az storage queue exists --name "$Q" --account-name "$STORAGE_ACCOUNT_NAME" --account-key "$STORAGE_KEY" --query exists -o tsv 2>/dev/null || echo "false")
        if [[ "$EXISTS" == "true" ]]; then
            check_pass "Queue exists: $Q"
        else
            check_fail "Queue missing: $Q"
        fi
    done
fi

# ---------------------------------------------------------------------------
# 5. Misconfiguration Targets
# ---------------------------------------------------------------------------
echo ""
echo "--- Misconfiguration Targets ---"

# Check prod-open-nsg
if az network nsg show --name "prod-open-nsg" --resource-group "rg-production" --output none 2>/dev/null; then
    check_pass "NSG exists: prod-open-nsg (rg-production)"
else
    check_warn "NSG missing: prod-open-nsg — CC6 tests will skip"
fi

# Check dev-open-nsg
if az network nsg show --name "dev-open-nsg" --resource-group "rg-development" --output none 2>/dev/null; then
    check_pass "NSG exists: dev-open-nsg (rg-development)"
else
    check_warn "NSG missing: dev-open-nsg — CC6 tests will skip"
fi

# Check storage account public access
if az storage account show --name "aiuc1prodstorage" --resource-group "rg-production" --output none 2>/dev/null; then
    PUBLIC=$(az storage account show --name "aiuc1prodstorage" --resource-group "rg-production" --query allowBlobPublicAccess -o tsv 2>/dev/null || echo "unknown")
    if [[ "$PUBLIC" == "true" ]]; then
        check_pass "Storage aiuc1prodstorage has public access (intentional misconfig for CC5)"
    else
        check_warn "Storage aiuc1prodstorage public access: $PUBLIC"
    fi
else
    check_warn "Storage account aiuc1prodstorage missing — CC5 tests will skip"
fi

# Check SQL server
if az sql server show --name "grclab-sql-02" --resource-group "rg-production" --output none 2>/dev/null; then
    check_pass "SQL Server exists: grclab-sql-02 (rg-production)"
else
    check_warn "SQL Server missing: grclab-sql-02 — CC7 tests will skip"
fi

# ---------------------------------------------------------------------------
# 6. RBAC Assignments
# ---------------------------------------------------------------------------
echo ""
echo "--- RBAC Assignments ---"
if [[ -n "$FA_MI" ]]; then
    ROLES=$(az role assignment list --assignee "$FA_MI" --query "[].roleDefinitionName" -o tsv 2>/dev/null || echo "")
    if echo "$ROLES" | grep -q "Reader"; then
        check_pass "Function App MI has Reader role"
    else
        check_fail "Function App MI missing Reader role"
    fi
    # Also check storage-scoped roles
    STORAGE_SCOPE="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT_NAME"
    STORAGE_ROLES=$(az role assignment list --assignee "$FA_MI" --scope "$STORAGE_SCOPE" --query "[].roleDefinitionName" -o tsv 2>/dev/null || echo "")
    ALL_ROLES="$ROLES $STORAGE_ROLES"
    if echo "$ALL_ROLES" | grep -q "Storage Queue Data Contributor"; then
        check_pass "Function App MI has Storage Queue Data Contributor"
    else
        check_fail "Function App MI missing Storage Queue Data Contributor"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo -e "  ${YELLOW}WARN: $WARN${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some checks failed. Fix the issues above before testing.${NC}"
    exit 1
else
    echo -e "${GREEN}All critical checks passed. Ready for live testing!${NC}"
    exit 0
fi
