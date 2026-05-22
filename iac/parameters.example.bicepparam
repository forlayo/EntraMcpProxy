// =============================================================================
// EntraMcpProxy — Bicep parameter file
// =============================================================================
// USAGE:
//   1. Provision the Entra app registration first:
//        bash iac/setup-entra-app.sh         (or .ps1)
//      That prints the values you paste below.
//   2. Copy this file to parameters.bicepparam (tracked in .gitignore).
//   3. Fill in every <placeholder>.
//   4. Run: bash iac/deploy.sh --resource-group <your-rg>
//      or:  pwsh iac/deploy.ps1 -ResourceGroup <your-rg>
// =============================================================================

using 'main.bicep'

// ---------------------------------------------------------------------------
// REQUIRED — Azure infrastructure references
// ---------------------------------------------------------------------------

// Name of the existing Azure Container Apps environment (in the same RG).
// Create one with: az containerapp env create --name <name> ...
param containerAppsEnvironmentName = '<your-aca-environment-name>'

// Name of the Azure Container Registry that holds the proxy image.
// Do NOT include the .azurecr.io suffix.
// The image must already be pushed: <acr>.azurecr.io/entra-mcp-proxy:1.0.0
param acrName = '<your-acr-name>'

// The organisation segment in https://mcp.dev.azure.com/{org}.
// Example: if your ADO URL is https://dev.azure.com/contoso, enter 'contoso'.
param azureDevOpsOrganization = '<your-ado-org-name>'

// ---------------------------------------------------------------------------
// REQUIRED — Entra app registration (from iac/setup-entra-app.sh|.ps1)
// ---------------------------------------------------------------------------

// Directory (tenant) GUID. Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
param entraTenantId = '<your-tenant-guid>'

// Application (client) GUID from the Entra app registration the setup script
// printed.
param entraClientId = '<your-client-app-guid>'

// ---------------------------------------------------------------------------
// REQUIRED — Secret source
// ---------------------------------------------------------------------------
// 'Direct' (default, recommended for first deployments and most production
//          setups): the OBO client secret is passed below as a @secure()
//          parameter and stored directly in the Container App secret store.
//          Azure scrubs @secure() params from deployment logs — the value
//          never appears in plain text in any Azure surface.
//
// 'KeyVault' (advanced, opt-in): the secret stays in Key Vault and the
//          Container App's managed identity reads it at runtime via
//          'Key Vault Secrets User'. Better for organisations with a
//          hardened KV rotation pipeline. Has a 1-2 min RBAC propagation
//          window that can fail the first revision — re-run the deploy
//          after the role assignment propagates.

param secretSource = 'Direct'

// The OBO client secret value. iac/setup-entra-app.sh prints this.
// Required when secretSource = 'Direct'. Pass via CI variable, GitHub
// secret, or interactive prompt — never commit it.
param oboClientSecretValue = '<the-secret-value-printed-by-setup-entra-app>'

// Only used when secretSource = 'KeyVault'. Leave as placeholder in Direct mode.
// param keyVaultName = '<your-keyvault-name>'

// Only used when secretSource = 'KeyVault'. Default: 'entra-mcp-proxy-client-secret'.
// param clientSecretSecretName = 'entra-mcp-proxy-client-secret'

// ---------------------------------------------------------------------------
// OPTIONAL — safe defaults are pre-set; uncomment to override
// ---------------------------------------------------------------------------

// Container App resource name (default: 'entra-mcp-proxy').
// Set this to the existing app's name if you already created the ACA app
// — Bicep will UPDATE that app rather than creating a new one.
// param appName = 'entra-mcp-proxy'

// Image repository inside ACR — the value between '<acr>.azurecr.io/' and ':<tag>'.
// Example: if you pushed `<acr>.azurecr.io/entra-mcp-proxy:1.0.0`,
// the repository is `entra-mcp-proxy` (the default).
// param imageRepository = 'entra-mcp-proxy'

// Image tag to deploy (default: '1.0.0').
// param imageTag = '1.0.0'

// Azure region (default: resource group location).
// param location = 'eastus'

// Replicas (defaults: min=1, max=3).
// param minReplicas = 1
// param maxReplicas = 3

// vCPU + memory per replica (defaults: 0.5 vCPU, 1Gi).
// param cpu = '0.5'
// param memory = '1Gi'

// Redirect URI the Entra app registration accepts (default: claude.ai callback).
// Only change this for non-production testing.
// param allowedRedirectUri = 'https://claude.ai/api/mcp/auth_callback'

// Outbound hostname allowlist for downstream connections.
// First entry must be mcp.dev.azure.com. Add more downstream hosts as needed.
// param egressAllowlist = ['mcp.dev.azure.com']

// Custom public base URL (leave empty to derive from ACA env's default domain).
// Set this if you have configured a custom domain on the Container App.
// param customPublicBaseUrl = 'https://mcp.contoso.com'

// OBO target scope for Azure DevOps Remote MCP (default: known resource GUID).
// param oboTargetScope = '2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools'

// Identity used to pull the image from ACR. Two options:
//   'system-environment' (DEFAULT) — use the ACA Environment's managed identity.
//        Works out-of-the-box when the platform team has already granted
//        AcrPull on the shared ACR to the environment's identity.
//   'system' — use THIS app's own system-assigned managed identity. Bicep
//        creates the AcrPull role assignment automatically. Requires Owner /
//        User Access Administrator on the ACR.
// param registryIdentityMode = 'system-environment'
