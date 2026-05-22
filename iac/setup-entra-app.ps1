#!/usr/bin/env pwsh
#Requires -Version 7

<#
.SYNOPSIS
    Provision the Entra app registration for EntraMcpProxy.

.DESCRIPTION
    Creates a Microsoft Entra (Azure AD) application registration configured
    precisely as EntraMcpProxy needs it. Idempotent — re-running against an
    existing app with the same display name updates it in place.

    What it configures:
      * Single-tenant sign-in audience
      * Web redirect URI         https://claude.ai/api/mcp/auth_callback
      * publicClient             false (proxy itself is confidential)
      * isFallbackPublicClient   TRUE — the non-obvious flag that lets device
                                 code grant work for the test script. Without
                                 it Entra returns AADSTS7000218 after sign-in
                                 even when a valid client_secret is sent.
                                 Does NOT weaken authorization-code/OBO flows.
      * identifierUris           api://{client-id}
      * Exposed scope            user_impersonation (delegated)
      * Required permission      Ado.Mcp.Tools (delegated, on resource
                                 2a72489c-aab2-4b65-b93a-a91edccf33b8)
      * Service principal        created in the local tenant
      * Admin consent            granted (needs Cloud Application Administrator)
      * Client secret            fresh, 2-year lifetime

.PARAMETER Name
    App display name. Default: EntraMcpProxy.

.PARAMETER RedirectUri
    OAuth redirect URI. Default: https://claude.ai/api/mcp/auth_callback.

.EXAMPLE
    pwsh iac/setup-entra-app.ps1

.EXAMPLE
    pwsh iac/setup-entra-app.ps1 -Name MyProxyApp
#>

[CmdletBinding()]
param(
    [string] $Name = 'EntraMcpProxy',
    [string] $RedirectUri = 'https://claude.ai/api/mcp/auth_callback'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft-owned constants
$AdoRemoteMcpAppId      = '2a72489c-aab2-4b65-b93a-a91edccf33b8'
$AdoRemoteMcpScopeValue = 'Ado.Mcp.Tools'
$SecretLifetimeYears    = 2

function Write-Step([string]$m)    { Write-Host "`n>> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)      { Write-Host "   $m"   -ForegroundColor Green }
function Write-Warn([string]$m)    { Write-Host "   WARNING: $m" -ForegroundColor Yellow }
function Write-FailExit([string]$m){ Write-Host "   ERROR: $m" -ForegroundColor Red; exit 1 }

# ── 1. Prerequisites ────────────────────────────────────────────────────────

Write-Step "Step 1/9 — Verify prerequisites"
foreach ($cmd in 'az') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-FailExit "Missing required command: $cmd"
    }
}
$tenantId = az account show --query tenantId -o tsv 2>$null
if (-not $tenantId) { Write-FailExit "Not logged in. Run: az login" }
Write-Ok "Tenant: $tenantId"
Write-Ok "Signed-in user: $(az account show --query user.name -o tsv)"

# ── 2. Resolve ADO Remote MCP scope ─────────────────────────────────────────

Write-Step "Step 2/9 — Resolve Azure DevOps Remote MCP scope GUID"
$adoScopeId = az ad sp show --id $AdoRemoteMcpAppId `
    --query "oauth2PermissionScopes[?value=='$AdoRemoteMcpScopeValue'].id | [0]" `
    -o tsv 2>$null

if (-not $adoScopeId) {
    Write-Warn "ADO Remote MCP service principal not present in tenant — attempting to create it."
    az ad sp create --id $AdoRemoteMcpAppId | Out-Null
    $adoScopeId = az ad sp show --id $AdoRemoteMcpAppId `
        --query "oauth2PermissionScopes[?value=='$AdoRemoteMcpScopeValue'].id | [0]" -o tsv
}
if (-not $adoScopeId) { Write-FailExit "Could not resolve Ado.Mcp.Tools scope id" }
Write-Ok "Scope id: $adoScopeId"

# ── 3. Create or re-use app ─────────────────────────────────────────────────

Write-Step "Step 3/9 — Create or re-use app '$Name'"
$existing = az ad app list --display-name $Name `
    --query "[?displayName=='$Name'] | [0]" -o json 2>$null | ConvertFrom-Json

if ($existing -and $existing.appId) {
    $appId       = $existing.appId
    $appObjectId = $existing.id
    Write-Warn "App with this name already exists — updating it in place."
    Write-Ok "Re-using App ID: $appId"
} else {
    $created     = az ad app create --display-name $Name --sign-in-audience AzureADMyOrg --web-redirect-uris $RedirectUri | ConvertFrom-Json
    $appId       = $created.appId
    $appObjectId = $created.id
    Write-Ok "Created App ID: $appId"
}
Write-Ok "Object ID:  $appObjectId"

# ── 4. identifierUris + isFallbackPublicClient ──────────────────────────────

Write-Step "Step 4/9 — Set identifierUris and isFallbackPublicClient"
$body4 = @{
    identifierUris         = @("api://$appId")
    isFallbackPublicClient = $true
    web                    = @{ redirectUris = @($RedirectUri) }
} | ConvertTo-Json -Compress -Depth 5
$body4 | az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
    --headers "Content-Type=application/json" `
    --body '@-' | Out-Null
Write-Ok "identifierUris=api://$appId  isFallbackPublicClient=true  redirectUri=$RedirectUri"

# ── 5. Expose user_impersonation scope ──────────────────────────────────────

Write-Step "Step 5/9 — Expose 'user_impersonation' delegated scope"
$userImpScopeId = [guid]::NewGuid().ToString()
$body5 = @{
    api = @{
        oauth2PermissionScopes = @(@{
            id                      = $userImpScopeId
            adminConsentDescription = 'Allow the application to access EntraMcpProxy on behalf of the signed-in user.'
            adminConsentDisplayName = 'Access EntraMcpProxy'
            isEnabled               = $true
            type                    = 'User'
            userConsentDescription  = 'Allow the application to access EntraMcpProxy on your behalf.'
            userConsentDisplayName  = 'Access EntraMcpProxy'
            value                   = 'user_impersonation'
        })
    }
} | ConvertTo-Json -Compress -Depth 6
$body5 | az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
    --headers "Content-Type=application/json" `
    --body '@-' | Out-Null
Write-Ok "Scope 'user_impersonation' exposed (id $userImpScopeId)"

# ── 6. Required permission Ado.Mcp.Tools ────────────────────────────────────

Write-Step "Step 6/9 — Add delegated permission Ado.Mcp.Tools"
$body6 = @{
    requiredResourceAccess = @(@{
        resourceAppId  = $AdoRemoteMcpAppId
        resourceAccess = @(@{
            id   = $adoScopeId
            type = 'Scope'
        })
    })
} | ConvertTo-Json -Compress -Depth 6
$body6 | az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
    --headers "Content-Type=application/json" `
    --body '@-' | Out-Null
Write-Ok "Delegated permission requested"

# ── 7. Service principal ────────────────────────────────────────────────────

Write-Step "Step 7/9 — Ensure service principal exists"
$spExists = az ad sp show --id $appId 2>$null
if (-not $spExists) {
    az ad sp create --id $appId | Out-Null
    Write-Ok "Service principal created"
} else {
    Write-Ok "Service principal already exists"
}

# ── 8. Admin consent ────────────────────────────────────────────────────────

Write-Step "Step 8/9 — Grant admin consent for delegated permissions"
try {
    az ad app permission admin-consent --id $appId 2>$null
    Write-Ok "Admin consent granted"
} catch {
    Write-Warn "Admin consent could not be granted by this user."
    Write-Warn "Have a Cloud Application Administrator run:"
    Write-Warn "    az ad app permission admin-consent --id $appId"
}

# ── 9. Fresh client secret ──────────────────────────────────────────────────

Write-Step "Step 9/9 — Mint a fresh client secret (lifetime ${SecretLifetimeYears}y)"
$today = (Get-Date).ToString('yyyy-MM-dd')
$secretJson = az ad app credential reset `
    --id $appObjectId `
    --years $SecretLifetimeYears `
    --append `
    --display-name "EntraMcpProxy ($today)" `
    -o json | ConvertFrom-Json
$clientSecret = $secretJson.password
$secretEnd    = $secretJson.endDateTime
Write-Ok "Secret created, expires $secretEnd"

# ── Summary ─────────────────────────────────────────────────────────────────

@"

================================================================================
APP REGISTRATION READY
================================================================================

Paste these into your iac/parameters.bicepparam:

    param entraTenantId        = '$tenantId'
    param entraClientId        = '$appId'
    param secretSource         = 'Direct'
    param oboClientSecretValue = '$clientSecret'

Also useful:
    App object id:     $appObjectId
    Redirect URI:      $RedirectUri
    Secret expires:    $secretEnd

IMPORTANT
  - The client secret is printed ONCE. Save it now (Bitwarden, 1Password, KV).
    Entra cannot reveal it again. If you lose it, re-run this script — the
    --append flag means a new secret is added without invalidating existing
    ones.
  - Verify in the Azure portal: https://entra.microsoft.com →
    App registrations → $Name → Authentication blade —
    "Allow public client flows" should read "Yes".

NEXT STEPS
  1. Fill the rest of parameters.bicepparam (containerAppsEnvironmentName,
     acrName, azureDevOpsOrganization, …).
  2. pwsh iac/deploy.ps1 -ResourceGroup <your-rg>
  3. bash iac/test/test-mcp.sh ``
         --tenant-id     $tenantId ``
         --client-id     $appId ``
         --client-secret '$clientSecret' ``
         --proxy-url     <output from deploy.ps1>
"@ | Write-Host
