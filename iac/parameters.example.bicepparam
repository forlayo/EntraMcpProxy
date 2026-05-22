// =============================================================================
// EntraMcpProxy — Bicep parameter file
// =============================================================================
// USAGE:
//   1. Copy this file to parameters.bicepparam (tracked in .gitignore)
//   2. Replace every <placeholder> with your real values
//   3. Run: pwsh iac/deploy.ps1 -ResourceGroup <your-rg>
//      or:  bash iac/deploy.sh --resource-group <your-rg>
// =============================================================================

using 'main.bicep'

// ---------------------------------------------------------------------------
// REQUIRED — you must supply all six of these
// ---------------------------------------------------------------------------

// Name of the existing Azure Container Apps environment (in the same RG).
// Create one with: az containerapp env create --name <name> ...
param containerAppsEnvironmentName = '<your-aca-environment-name>'

// Name of the Azure Container Registry that holds the proxy image.
// Do NOT include the .azurecr.io suffix.
// The image must already be pushed: acrsharedservicesglobal01.azurecr.io/entra-mcp-proxy:1.0.0
param acrName = '<your-acr-name>'

// Directory (tenant) GUID from Azure Entra ID → Overview.
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
param entraTenantId = '<your-tenant-guid>'

// Application (client) GUID from the Entra app registration.
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
param entraClientId = '<your-client-app-guid>'

// The organisation segment in https://mcp.dev.azure.com/{org}
// Example: if your ADO URL is https://dev.azure.com/contoso, enter 'contoso'
param azureDevOpsOrganization = '<your-ado-org-name>'

// Name of the existing Azure Key Vault that holds the OBO client secret.
// The secret named 'entra-mcp-proxy-client-secret' (default) must exist inside it.
param keyVaultName = '<your-keyvault-name>'

// ---------------------------------------------------------------------------
// OPTIONAL — safe defaults are pre-set; uncomment to override
// ---------------------------------------------------------------------------

// Container App resource name (default: 'entra-mcp-proxy').
// Set this to the existing app's name if you already created the ACA app
// — Bicep will UPDATE that app rather than creating a new one.
// param appName = 'entra-mcp-proxy'

// Image repository inside ACR — the value between '<acr>.azurecr.io/' and ':<tag>'.
// This is what you pushed with `docker push`; it is NOT the Container App's name.
// Example: if you pushed `acrsharedservicesglobal01.azurecr.io/entra-mcp-proxy:1.0.0`,
// the repository is `entra-mcp-proxy` (the default).
// param imageRepository = 'entra-mcp-proxy'

// Image tag to deploy (default: '1.0.0')
// param imageTag = '1.0.0'

// Name of the secret inside Key Vault (default: 'entra-mcp-proxy-client-secret')
// param clientSecretSecretName = 'entra-mcp-proxy-client-secret'

// Azure region (default: resource group location)
// param location = 'eastus'

// Minimum replica count — keep at 1 for warm standby (default: 1)
// param minReplicas = 1

// Maximum replica count (default: 3)
// param maxReplicas = 3

// vCPU per replica (default: '0.5')
// param cpu = '0.5'

// Memory per replica (default: '1Gi')
// param memory = '1Gi'

// Redirect URI the Entra app registration accepts (default: claude.ai callback)
// Only change this if you are using a non-production claude.ai tenant.
// param allowedRedirectUri = 'https://claude.ai/api/mcp/auth_callback'

// Outbound hostname allowlist for downstream connections.
// The first entry must be mcp.dev.azure.com. Add more downstream hosts as needed.
// param egressAllowlist = ['mcp.dev.azure.com']

// Custom public base URL (leave empty to derive from ACA env's default domain).
// Set this if you have configured a custom domain on the Container App.
// Example: 'https://mcp.contoso.com'
// param customPublicBaseUrl = ''

// OBO target scope for Azure DevOps Remote MCP (default is the known resource GUID).
// Only change this if Microsoft updates the Azure DevOps Remote MCP resource ID.
// param oboTargetScope = '2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools'

// Identity used to pull the image from ACR. Two options:
//   'system-environment' (DEFAULT) — use the ACA Environment's managed identity.
//        Works out-of-the-box when the platform team has already granted
//        AcrPull on the shared ACR to the environment's identity. This is the
//        typical setup for org-wide shared ACRs (acrsharedservices*).
//   'system' — use THIS app's own system-assigned managed identity.
//        Bicep will create the AcrPull role assignment on the ACR automatically.
//        Only use this if you have Owner or User Access Administrator on the ACR.
// param registryIdentityMode = 'system-environment'

// =========================================================================
// SECRET SOURCE — pick ONE
// =========================================================================
// How the OBO client_secret reaches the running container. Two options:
//
//   'KeyVault' (production-grade): the secret stays in Key Vault, the
//      Container App references it at runtime via its managed identity.
//      Requires `Key Vault Secrets User` on the KV — which the Bicep
//      creates, but it has a RACE CONDITION on first deploy: RBAC
//      propagation can take 1-2 min, and during that window the new
//      revision tries to resolve the secret and fails. ACA marks the
//      revision as Failed and keeps serving the previous one. To use
//      this mode safely, either pre-create the role assignment manually
//      (so it's propagated before the deploy), or run the deploy TWICE
//      — the second run picks up where the first left off because RBAC
//      has propagated by then.
//
//   'Direct' (simpler, no race): the secret value is passed as a @secure()
//      parameter at deploy time and stored directly in the Container App
//      secret. No KV dependency, no race condition. The secret value
//      never appears in deployment logs (Azure scrubs @secure() params).
//      Recommended for first deployments; switch to KeyVault once the
//      platform side is stable.
//
// param secretSource = 'KeyVault'    // default; production-grade
// param secretSource = 'Direct'      // simpler; required when RBAC race blocks deploy

// REQUIRED when secretSource = 'Direct': the actual secret value.
// Pass it via Azure DevOps pipeline variable, GitHub secret, or interactively
// on the CLI — NEVER commit it to source control.
// param oboClientSecretValue = '<the-real-secret-value>'
