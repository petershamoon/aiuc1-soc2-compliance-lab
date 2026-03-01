#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Azure Environment Setup
# ---------------------------------------------------------------------------
# One-shot script to prepare the Azure environment for live testing.
# Run this AFTER you have:
#   1. Logged into Azure CLI: az login
#   2. Set the correct subscription: az account set -s <subscription_id>
#   3. Filled in .env with real values
#
# What this script does:
#   1. Creates the 24 Storage Queues (12 input + 12 output)
#   2. Assigns RBAC roles for Managed Identities
#   3. Deploys the Function App code
#   4. Validates the deployment
#
# Usage:
#   chmod +x scripts/setup_azure.sh
#   ./scripts/setup_azure.sh
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — Edit these or source from .env
# ---------------------------------------------------------------------------
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
RESOURCE_GROUP="${RESOURCE_GROUP_FOUNDRY:-rg-aiuc1-foundry}"
FUNCTION_APP_NAME="${FUNCTION_APP_NAME:-aiuc1-soc2-tools}"
STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-<REDACTED-STORAGE>}"
LOCATION="${AZURE_LOCATION:-eastus2}"

# Managed Identity Principal IDs (from skill file)
HUB_MI_PRINCIPAL="${HUB_MI_PRINCIPAL:-}"
PROJECT_MI_PRINCIPAL="${PROJECT_MI_PRINCIPAL:-}"
FUNC_APP_MI_PRINCIPAL="${FUNC_APP_MI_PRINCIPAL:-}"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "Running pre-flight checks..."

if ! command -v az &>/dev/null; then
    error "Azure CLI not found. Install with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
    exit 1
fi

if ! command -v func &>/dev/null; then
    warn "Azure Functions Core Tools not found. Install with:"
    warn "  npm install -g azure-functions-core-tools@4 --unsafe-perm true"
    warn "  (Only needed for local testing, not for deployment)"
fi

CURRENT_SUB=$(az account show --query id -o tsv 2>/dev/null || echo "")
if [[ "$CURRENT_SUB" != "$SUBSCRIPTION_ID" ]]; then
    info "Setting subscription to $SUBSCRIPTION_ID..."
    az account set --subscription "$SUBSCRIPTION_ID"
fi

info "Subscription: $(az account show --query '{name:name, id:id}' -o tsv)"

# ---------------------------------------------------------------------------
# Step 1: Create Storage Queues
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Step 1: Creating Storage Queues"
info "=========================================="

FUNCTIONS=(
    "gap-analyzer"
    "scan-cc-criteria"
    "evidence-validator"
    "query-access-controls"
    "query-defender-score"
    "query-policy-compliance"
    "generate-poam-entry"
    "run-terraform-plan"
    "run-terraform-apply"
    "git-commit-push"
    "sanitize-output"
    "log-security-event"
)

# Get storage account key
STORAGE_KEY=$(az storage account keys list \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query '[0].value' -o tsv)

if [[ -z "$STORAGE_KEY" ]]; then
    error "Failed to get storage account key for $STORAGE_ACCOUNT_NAME"
    exit 1
fi

info "Storage account key retrieved for $STORAGE_ACCOUNT_NAME"

for func in "${FUNCTIONS[@]}"; do
    for suffix in "input" "output"; do
        QUEUE_NAME="${func}-${suffix}"
        if az storage queue create \
            --name "$QUEUE_NAME" \
            --account-name "$STORAGE_ACCOUNT_NAME" \
            --account-key "$STORAGE_KEY" \
            --output none 2>/dev/null; then
            info "  Queue created/exists: $QUEUE_NAME"
        else
            warn "  Failed to create queue: $QUEUE_NAME (may already exist)"
        fi
    done
done

info "All 24 queues created."

# ---------------------------------------------------------------------------
# Step 2: Assign RBAC Roles
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Step 2: Assigning RBAC Roles"
info "=========================================="

STORAGE_RESOURCE_ID=$(az storage account show \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

QUEUE_CONTRIBUTOR_ROLE="974c5e8b-45b9-4653-ba55-5f855dd0fb88"  # Storage Queue Data Contributor

assign_role() {
    local PRINCIPAL_ID="$1"
    local LABEL="$2"
    if [[ -z "$PRINCIPAL_ID" ]]; then
        warn "  Skipping $LABEL — no principal ID provided"
        return
    fi
    if az role assignment create \
        --assignee-object-id "$PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "$QUEUE_CONTRIBUTOR_ROLE" \
        --scope "$STORAGE_RESOURCE_ID" \
        --output none 2>/dev/null; then
        info "  Assigned Storage Queue Data Contributor to $LABEL ($PRINCIPAL_ID)"
    else
        warn "  Role assignment for $LABEL may already exist (this is OK)"
    fi
}

assign_role "$HUB_MI_PRINCIPAL" "Hub Managed Identity"
assign_role "$PROJECT_MI_PRINCIPAL" "Project Managed Identity"
assign_role "$FUNC_APP_MI_PRINCIPAL" "Function App Managed Identity"

# Also assign Reader role to Function App MI at subscription level
if [[ -n "$FUNC_APP_MI_PRINCIPAL" ]]; then
    if az role assignment create \
        --assignee-object-id "$FUNC_APP_MI_PRINCIPAL" \
        --assignee-principal-type ServicePrincipal \
        --role "Reader" \
        --scope "/subscriptions/$SUBSCRIPTION_ID" \
        --output none 2>/dev/null; then
        info "  Assigned Reader (subscription) to Function App MI"
    else
        warn "  Reader role for Function App MI may already exist"
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: Configure Function App Settings
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Step 3: Configuring Function App Settings"
info "=========================================="

# Set the storage connection string for queue triggers
STORAGE_CONN_STR=$(az storage account show-connection-string \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query connectionString -o tsv)

az functionapp config appsettings set \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --settings \
        "AzureWebJobsStorage=$STORAGE_CONN_STR" \
        "AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID" \
        "RESOURCE_GROUP_FOUNDRY=$RESOURCE_GROUP" \
        "RESOURCE_GROUP_PRODUCTION=rg-production" \
        "RESOURCE_GROUP_DEVELOPMENT=rg-development" \
        "TERRAFORM_WORKING_DIR=/home/site/wwwroot/terraform" \
        "TERRAFORM_APPROVAL_SECRET=$(openssl rand -hex 32)" \
    --output none

info "Function App settings configured."

# ---------------------------------------------------------------------------
# Step 4: Deploy Function App Code
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Step 4: Deploying Function App Code"
info "=========================================="

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUNCTIONS_DIR="$REPO_ROOT/functions"

if [[ ! -f "$FUNCTIONS_DIR/function_app.py" ]]; then
    error "function_app.py not found at $FUNCTIONS_DIR"
    exit 1
fi

info "Deploying from $FUNCTIONS_DIR..."

cd "$FUNCTIONS_DIR"

# Deploy using zip deploy
func azure functionapp publish "$FUNCTION_APP_NAME" --python 2>&1 || {
    warn "func CLI deploy failed. Trying zip deploy via az CLI..."
    
    # Fallback: zip deploy
    DEPLOY_ZIP="/tmp/aiuc1-functions.zip"
    cd "$FUNCTIONS_DIR"
    zip -r "$DEPLOY_ZIP" . -x "__pycache__/*" ".pytest_cache/*" "*.pyc" ".env" 2>/dev/null
    
    az functionapp deployment source config-zip \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --src "$DEPLOY_ZIP" \
        --output none
    
    rm -f "$DEPLOY_ZIP"
}

info "Function App deployed."

# ---------------------------------------------------------------------------
# Step 5: Validate Deployment
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Step 5: Validating Deployment"
info "=========================================="

# Check function app is running
STATUS=$(az functionapp show \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query state -o tsv)

if [[ "$STATUS" == "Running" ]]; then
    info "Function App status: $STATUS"
else
    error "Function App status: $STATUS (expected Running)"
fi

# List deployed functions via admin API
MASTER_KEY=$(az functionapp keys list \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query masterKey -o tsv 2>/dev/null || echo "")

if [[ -n "$MASTER_KEY" ]]; then
    info "Checking deployed functions..."
    FUNC_LIST=$(curl -s "https://${FUNCTION_APP_NAME}.azurewebsites.net/admin/functions" \
        -H "x-functions-key: $MASTER_KEY" 2>/dev/null || echo "[]")
    FUNC_COUNT=$(echo "$FUNC_LIST" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    info "  Deployed functions: $FUNC_COUNT (expected: 12)"
else
    warn "Could not retrieve master key. Check functions manually in the portal."
fi

# Check queue count
QUEUE_COUNT=$(az storage queue list \
    --account-name "$STORAGE_ACCOUNT_NAME" \
    --account-key "$STORAGE_KEY" \
    --query "length(@)" -o tsv 2>/dev/null || echo "0")
info "  Storage queues: $QUEUE_COUNT (expected: 24)"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
info ""
info "=========================================="
info "Setup Complete!"
info "=========================================="
info ""
info "Next steps:"
info "  1. Register the agent tools:  python3 scripts/register_agent_tools.py"
info "  2. Run the manual tests:      See MANUAL_TESTING_GUIDE.md"
info "  3. Run the automated tests:   python3 -m pytest tests/ -v"
info ""
info "Storage account key (save this for the agent prompt):"
info "  $STORAGE_KEY"
