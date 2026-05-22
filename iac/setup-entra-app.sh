#!/usr/bin/env bash
# =============================================================================
# setup-entra-app.sh — Provision the Entra app registration for EntraMcpProxy
# =============================================================================
# Creates a Microsoft Entra (Azure AD) application registration configured
# precisely as EntraMcpProxy needs it. Idempotent against an already-existing
# app with the same display name (re-uses it instead of failing).
#
# What it configures
# ------------------
#   * Single-tenant sign-in audience
#   * Web platform redirect URI         https://claude.ai/api/mcp/auth_callback
#   * publicClient                      false (the proxy itself is confidential)
#   * isFallbackPublicClient            TRUE — this is the non-obvious flag that
#                                       lets device-code flow (used by the test
#                                       script iac/test/test-mcp.sh) work AGAINST
#                                       a confidential app. Without it, Entra
#                                       returns AADSTS7000218 after user sign-in
#                                       even when a valid client_secret is sent.
#                                       It does NOT weaken the confidential
#                                       authorization-code or OBO flows.
#   * identifierUris                    api://{client-id}
#   * Exposed scope                     user_impersonation (delegated, user+admin
#                                       consent)
#   * Required delegated permission     Ado.Mcp.Tools on the Azure DevOps Remote
#                                       MCP application (resource appId
#                                       2a72489c-aab2-4b65-b93a-a91edccf33b8)
#   * Service principal                 created in the local tenant
#   * Admin consent                     granted on the proxy app's own scope and
#                                       on Ado.Mcp.Tools (requires the executing
#                                       user to hold Cloud Application
#                                       Administrator or higher)
#   * Client secret                     fresh, 2-year lifetime
#
# Prerequisites
# -------------
#   * Azure CLI ≥ 2.60 (az --version)
#   * jq
#   * az login as a user who can create app registrations AND grant tenant-wide
#     admin consent (Cloud Application Administrator / Global Administrator).
#     Lower-privileged users can run the script up to the consent-grant step;
#     hand the printed `az ad app permission admin-consent` command to an admin.
#
# Output
# ------
# A copy-pasteable block for iac/parameters.bicepparam, plus the secret value
# (printed ONCE — Entra cannot return it again, so capture it).
#
# Usage
# -----
#   bash iac/setup-entra-app.sh                          # defaults
#   bash iac/setup-entra-app.sh --name MyProxyApp
#   bash iac/setup-entra-app.sh --redirect-uri https://claude.ai/api/mcp/auth_callback
#
# =============================================================================

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────

DISPLAY_NAME="EntraMcpProxy"
REDIRECT_URI="https://claude.ai/api/mcp/auth_callback"

# Microsoft-owned constants. Do NOT change unless Microsoft renames the
# Azure DevOps Remote MCP application or scope.
ADO_REMOTE_MCP_APP_ID="2a72489c-aab2-4b65-b93a-a91edccf33b8"
ADO_REMOTE_MCP_SCOPE_VALUE="Ado.Mcp.Tools"

SECRET_LIFETIME_YEARS=2

# ── ANSI helpers ────────────────────────────────────────────────────────────

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
step()    { printf "\n${CYAN}>> %s${RESET}\n" "$*"; }
ok()      { printf "   ${GREEN}%s${RESET}\n" "$*"; }
warn()    { printf "   ${YELLOW}WARNING: %s${RESET}\n" "$*"; }
fail()    { printf "   ${RED}ERROR: %s${RESET}\n" "$*"; exit 1; }

# ── Argument parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)         DISPLAY_NAME="$2"; shift 2 ;;
        --redirect-uri) REDIRECT_URI="$2"; shift 2 ;;
        -h|--help)
            grep -E '^#' "$0" | head -55 | sed 's/^# \?//'
            exit 0 ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

# ── 1. Prerequisites ────────────────────────────────────────────────────────

step "Step 1/9 — Verify prerequisites"
for cmd in az jq; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
done
ok "az + jq present"

TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null) \
    || fail "Not logged in to az. Run: az login"
ok "Tenant: $TENANT_ID"
ok "Signed-in user: $(az account show --query user.name -o tsv)"

# ── 2. Resolve the Azure DevOps Remote MCP scope ────────────────────────────

step "Step 2/9 — Resolve Azure DevOps Remote MCP scope GUID"
ADO_MCP_SCOPE_ID=$(az ad sp show --id "$ADO_REMOTE_MCP_APP_ID" \
    --query "oauth2PermissionScopes[?value=='$ADO_REMOTE_MCP_SCOPE_VALUE'].id | [0]" \
    -o tsv 2>/dev/null) || {
        warn "Azure DevOps Remote MCP service principal not found in this tenant."
        warn "Attempting to create it (requires Cloud Application Administrator)..."
        az ad sp create --id "$ADO_REMOTE_MCP_APP_ID" >/dev/null \
            || fail "Could not create ADO Remote MCP SP. Have an admin run: az ad sp create --id $ADO_REMOTE_MCP_APP_ID"
        ADO_MCP_SCOPE_ID=$(az ad sp show --id "$ADO_REMOTE_MCP_APP_ID" \
            --query "oauth2PermissionScopes[?value=='$ADO_REMOTE_MCP_SCOPE_VALUE'].id | [0]" -o tsv)
    }
[[ -n "$ADO_MCP_SCOPE_ID" ]] || fail "Could not resolve Ado.Mcp.Tools scope id"
ok "Scope id: $ADO_MCP_SCOPE_ID"

# ── 3. Create or re-use the app registration ────────────────────────────────

step "Step 3/9 — Create or re-use app '$DISPLAY_NAME'"
EXISTING_APP=$(az ad app list --display-name "$DISPLAY_NAME" \
    --query "[?displayName=='$DISPLAY_NAME'] | [0]" -o json 2>/dev/null)

if [[ "$EXISTING_APP" != "null" && -n "$EXISTING_APP" ]]; then
    APP_ID=$(echo "$EXISTING_APP" | jq -r .appId)
    APP_OBJECT_ID=$(echo "$EXISTING_APP" | jq -r .id)
    warn "App with this name already exists — updating it in place."
    ok "Re-using App ID: $APP_ID"
else
    CREATE_OUT=$(az ad app create \
        --display-name "$DISPLAY_NAME" \
        --sign-in-audience AzureADMyOrg \
        --web-redirect-uris "$REDIRECT_URI")
    APP_ID=$(echo "$CREATE_OUT" | jq -r .appId)
    APP_OBJECT_ID=$(echo "$CREATE_OUT" | jq -r .id)
    ok "Created App ID: $APP_ID"
fi
ok "Object ID:  $APP_OBJECT_ID"

# ── 4. identifierUris + isFallbackPublicClient ──────────────────────────────

step "Step 4/9 — Set identifierUris and isFallbackPublicClient"
# identifier URI must be api://{client-id}.  isFallbackPublicClient must be
# true to permit device-code grant against this otherwise-confidential client.
az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
    --headers "Content-Type=application/json" \
    --body "{
        \"identifierUris\": [\"api://$APP_ID\"],
        \"isFallbackPublicClient\": true,
        \"web\": { \"redirectUris\": [\"$REDIRECT_URI\"] }
    }" >/dev/null
ok "identifierUris=api://$APP_ID  isFallbackPublicClient=true  redirectUri=$REDIRECT_URI"

# ── 5. Expose user_impersonation scope ──────────────────────────────────────

step "Step 5/9 — Expose 'user_impersonation' delegated scope"
USER_IMP_SCOPE_ID=$(uuidgen 2>/dev/null | tr 'A-Z' 'a-z' \
    || python3 -c "import uuid; print(uuid.uuid4())")

SCOPE_JSON=$(jq -nc --arg id "$USER_IMP_SCOPE_ID" '{
    api: {
        oauth2PermissionScopes: [{
            id: $id,
            adminConsentDescription: "Allow the application to access EntraMcpProxy on behalf of the signed-in user.",
            adminConsentDisplayName: "Access EntraMcpProxy",
            isEnabled: true,
            type: "User",
            userConsentDescription: "Allow the application to access EntraMcpProxy on your behalf.",
            userConsentDisplayName: "Access EntraMcpProxy",
            value: "user_impersonation"
        }]
    }
}')

az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
    --headers "Content-Type=application/json" \
    --body "$SCOPE_JSON" >/dev/null
ok "Scope 'user_impersonation' exposed (id $USER_IMP_SCOPE_ID)"

# ── 6. Required permission on Ado.Mcp.Tools ─────────────────────────────────

step "Step 6/9 — Add delegated permission Ado.Mcp.Tools"
REQ_JSON=$(jq -nc --arg appId "$ADO_REMOTE_MCP_APP_ID" --arg scopeId "$ADO_MCP_SCOPE_ID" '{
    requiredResourceAccess: [{
        resourceAppId: $appId,
        resourceAccess: [{
            id: $scopeId,
            type: "Scope"
        }]
    }]
}')
az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
    --headers "Content-Type=application/json" \
    --body "$REQ_JSON" >/dev/null
ok "Delegated permission requested"

# ── 7. Service principal for this app ───────────────────────────────────────

step "Step 7/9 — Ensure service principal exists for this app"
if az ad sp show --id "$APP_ID" >/dev/null 2>&1; then
    ok "Service principal already exists"
else
    az ad sp create --id "$APP_ID" >/dev/null \
        || fail "Could not create service principal — requires Cloud Application Administrator"
    ok "Service principal created"
fi

# ── 8. Admin consent ────────────────────────────────────────────────────────

step "Step 8/9 — Grant admin consent for delegated permissions"
if az ad app permission admin-consent --id "$APP_ID" 2>/dev/null; then
    ok "Admin consent granted"
else
    warn "Admin consent could not be granted by this user account."
    warn "Have a Cloud Application Administrator run:"
    warn "    az ad app permission admin-consent --id $APP_ID"
fi

# ── 9. Fresh client secret ──────────────────────────────────────────────────

step "Step 9/9 — Mint a fresh client secret (lifetime ${SECRET_LIFETIME_YEARS}y)"
SECRET_OUT=$(az ad app credential reset \
    --id "$APP_OBJECT_ID" \
    --years "$SECRET_LIFETIME_YEARS" \
    --append \
    --display-name "EntraMcpProxy ($(date +%Y-%m-%d))" \
    -o json)
CLIENT_SECRET=$(echo "$SECRET_OUT" | jq -r .password)
SECRET_END=$(echo "$SECRET_OUT" | jq -r .endDateTime)
ok "Secret created, expires $SECRET_END"

# ── Summary ─────────────────────────────────────────────────────────────────

cat <<EOF

================================================================================
${GREEN}APP REGISTRATION READY${RESET}
================================================================================

Paste these into your iac/parameters.bicepparam:

    param entraTenantId        = '$TENANT_ID'
    param entraClientId        = '$APP_ID'
    param secretSource         = 'Direct'
    param oboClientSecretValue = '$CLIENT_SECRET'

Also useful:
    App object id:     $APP_OBJECT_ID
    Redirect URI:      $REDIRECT_URI
    Secret expires:    $SECRET_END

${YELLOW}IMPORTANT${RESET}
  - The client secret is printed ONCE. Save it now (Bitwarden, 1Password, KV).
    Entra cannot reveal it again. If you lose it, re-run this script — the
    --append flag means a new secret is added without invalidating any
    existing ones.
  - Verify everything looks right in the Azure portal:
    https://entra.microsoft.com → App registrations → $DISPLAY_NAME
    → Authentication blade — "Allow public client flows" should read "Yes".

NEXT STEPS
  1. Fill the rest of parameters.bicepparam (containerAppsEnvironmentName,
     acrName, azureDevOpsOrganization, …).
  2. bash iac/deploy.sh --resource-group <your-rg>
  3. bash iac/test/test-mcp.sh \\
         --tenant-id     $TENANT_ID \\
         --client-id     $APP_ID \\
         --client-secret '$CLIENT_SECRET' \\
         --proxy-url     <output from deploy.sh>

EOF
