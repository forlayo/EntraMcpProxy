#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Deploy EntraMcpProxy to Azure Container Apps
# =============================================================================
# Usage:
#   bash iac/deploy.sh --resource-group <rg-name>
#   bash iac/deploy.sh -g <rg-name> [--parameters <file>] [--name <deployment-name>]
#
# Runs a what-if diff first, prompts for confirmation, then deploys.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BICEP_FILE="${SCRIPT_DIR}/main.bicep"
PARAMETERS_FILE="${SCRIPT_DIR}/parameters.bicepparam"
RESOURCE_GROUP=""
DEPLOYMENT_NAME="entra-mcp-proxy-$(date +%Y%m%d%H%M%S)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
step()    { echo -e "\n\033[0;36m>> $*\033[0m"; }
success() { echo -e "   \033[0;32m$*\033[0m"; }
warn()    { echo -e "   \033[0;33mWARNING: $*\033[0m"; }
fail()    { echo -e "   \033[0;31mERROR: $*\033[0m"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--resource-group)
      RESOURCE_GROUP="$2"; shift 2 ;;
    --parameters)
      PARAMETERS_FILE="$2"; shift 2 ;;
    --name)
      DEPLOYMENT_NAME="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | head -12 | sed 's/^# \?//'
      exit 0 ;;
    *)
      fail "Unknown argument: $1"
      exit 1 ;;
  esac
done

if [[ -z "$RESOURCE_GROUP" ]]; then
  fail "--resource-group / -g is required."
  echo "  Usage: bash iac/deploy.sh --resource-group <rg-name>"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1 — Prerequisite checks
# ---------------------------------------------------------------------------
step "Checking prerequisites..."

# az CLI
if ! command -v az &>/dev/null; then
  fail "Azure CLI (az) is not installed or not on PATH."
  echo "  Install from: https://learn.microsoft.com/cli/azure/install-azure-cli"
  exit 1
fi
AZ_VERSION=$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo "unknown")
success "az CLI found: ${AZ_VERSION}"

# Login check
ACCOUNT_JSON=$(az account show 2>/dev/null || true)
if [[ -z "$ACCOUNT_JSON" ]]; then
  fail "Not logged in to Azure. Run: az login"
  exit 1
fi
ACCOUNT_USER=$(echo "$ACCOUNT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['user']['name'])" 2>/dev/null || echo "unknown")
ACCOUNT_SUB=$(echo "$ACCOUNT_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['name'])" 2>/dev/null || echo "unknown")
success "Logged in as : ${ACCOUNT_USER}"
success "Subscription : ${ACCOUNT_SUB}"

# Bicep — prefer az bicep, fall back to standalone bicep
if az bicep version &>/dev/null 2>&1; then
  success "Bicep available via 'az bicep'"
elif command -v bicep &>/dev/null; then
  success "Standalone bicep found: $(bicep --version)"
else
  warn "bicep CLI not found — attempting 'az bicep install'..."
  az bicep install
fi

# Files
if [[ ! -f "$PARAMETERS_FILE" ]]; then
  fail "Parameters file not found: ${PARAMETERS_FILE}"
  echo "  Copy iac/parameters.example.bicepparam to iac/parameters.bicepparam and fill in your values."
  exit 1
fi
success "Parameters file : ${PARAMETERS_FILE}"

if [[ ! -f "$BICEP_FILE" ]]; then
  fail "Bicep template not found: ${BICEP_FILE}"
  exit 1
fi
success "Bicep template  : ${BICEP_FILE}"

# ---------------------------------------------------------------------------
# Step 2 — Validate resource group
# ---------------------------------------------------------------------------
step "Validating resource group '${RESOURCE_GROUP}'..."

RG_LOCATION=$(az group show --name "$RESOURCE_GROUP" --query location -o tsv 2>/dev/null || true)
if [[ -z "$RG_LOCATION" ]]; then
  fail "Resource group '${RESOURCE_GROUP}' not found in current subscription."
  echo "  Create it with: az group create --name ${RESOURCE_GROUP} --location <location>"
  exit 1
fi
success "Resource group exists: ${RG_LOCATION}"

# ---------------------------------------------------------------------------
# Step 3 — What-if diff
# ---------------------------------------------------------------------------
step "Running what-if diff (no changes will be made)..."
echo ""

az deployment group what-if \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEPLOYMENT_NAME" \
  --template-file "$BICEP_FILE" \
  --parameters "$PARAMETERS_FILE" \
  --result-format FullResourcePayloads

# ---------------------------------------------------------------------------
# Step 4 — Confirmation
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  Review the changes above carefully before proceeding."
echo "================================================================"
echo ""
read -rp "Proceed with deployment? [y/N] " ANSWER

if [[ ! "$ANSWER" =~ ^[Yy]$ ]]; then
  echo "Deployment cancelled."
  exit 0
fi

# ---------------------------------------------------------------------------
# Step 5 — Deploy
# ---------------------------------------------------------------------------
step "Deploying '${DEPLOYMENT_NAME}' to resource group '${RESOURCE_GROUP}'..."
echo ""

DEPLOY_OUTPUT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEPLOYMENT_NAME" \
  --template-file "$BICEP_FILE" \
  --parameters "$PARAMETERS_FILE" \
  --output json)

# ---------------------------------------------------------------------------
# Step 6 — Print outputs
# ---------------------------------------------------------------------------
echo ""
echo -e "\033[0;32m================================================================"
echo "  DEPLOYMENT SUCCEEDED"
echo -e "================================================================\033[0m"
echo ""

FQDN=$(echo "$DEPLOY_OUTPUT"        | python3 -c "import sys,json; o=json.load(sys.stdin)['properties']['outputs']; print(o['appFqdn']['value'])" 2>/dev/null || echo "")
MCP_URL=$(echo "$DEPLOY_OUTPUT"     | python3 -c "import sys,json; o=json.load(sys.stdin)['properties']['outputs']; print(o['mcpEndpointUrl']['value'])" 2>/dev/null || echo "")
HEALTHZ=$(echo "$DEPLOY_OUTPUT"     | python3 -c "import sys,json; o=json.load(sys.stdin)['properties']['outputs']; print(o['healthzUrl']['value'])" 2>/dev/null || echo "")
DISCOVERY=$(echo "$DEPLOY_OUTPUT"   | python3 -c "import sys,json; o=json.load(sys.stdin)['properties']['outputs']; print(o['oauthDiscoveryUrl']['value'])" 2>/dev/null || echo "")
NEXT_STEPS=$(echo "$DEPLOY_OUTPUT"  | python3 -c "import sys,json; o=json.load(sys.stdin)['properties']['outputs']; print(o['nextStepsMessage']['value'])" 2>/dev/null || echo "")

if [[ -n "$FQDN" ]]; then
  echo "  App FQDN       : ${FQDN}"
  echo "  MCP Endpoint   : ${MCP_URL}"
  echo "  Health Check   : ${HEALTHZ}"
  echo "  OAuth Discovery: ${DISCOVERY}"
  echo ""
  echo -e "\033[0;36m${NEXT_STEPS}\033[0m"
else
  warn "Could not parse deployment outputs — deployment succeeded but output display failed."
  echo "$DEPLOY_OUTPUT"
fi
