// =============================================================================
// EntraMcpProxy — Azure Container Apps deployment
// =============================================================================
// Minimum-input philosophy: supply only deployment-specific values.
// Everything else is derived or has a safe default.
//
// Required parameters (6):
//   containerAppsEnvironmentName, acrName, entraTenantId, entraClientId,
//   azureDevOpsOrganization, keyVaultName
// =============================================================================

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------
// Required parameters
// ---------------------------------------------------------------------------

@description('Name of the existing Azure Container Apps environment (in the same RG).')
param containerAppsEnvironmentName string

@description('Name of the existing ACR — without the .azurecr.io suffix.')
param acrName string

@description('Entra ID directory (tenant) GUID.')
@minLength(36)
@maxLength(36)
param entraTenantId string

@description('Entra ID application (client) GUID.')
@minLength(36)
@maxLength(36)
param entraClientId string

@description('Azure DevOps organisation name — the {org} in https://mcp.dev.azure.com/{org}.')
param azureDevOpsOrganization string

@description('Name of the existing Key Vault that holds the OBO client secret.')
param keyVaultName string

// ---------------------------------------------------------------------------
// Optional parameters with safe defaults
// ---------------------------------------------------------------------------

@description('Name of the Container App resource.')
param appName string = 'entra-mcp-proxy'

@description('Image repository name inside the ACR — i.e. the value AFTER `<acr>.azurecr.io/` and BEFORE the colon. This is what you pushed with docker tag/push; it is NOT necessarily the same as the Container App name. Defaults to "entra-mcp-proxy".')
param imageRepository string = 'entra-mcp-proxy'

@description('Image tag to deploy.')
param imageTag string = '1.0.0'

@description('Name of the secret inside Key Vault that holds the OBO client_secret.')
param clientSecretSecretName string = 'entra-mcp-proxy-client-secret'

@description('Azure region. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Minimum replica count.')
@minValue(1)
@maxValue(10)
param minReplicas int = 1

@description('Maximum replica count.')
@minValue(1)
@maxValue(10)
param maxReplicas int = 3

@description('vCPU allocation per replica.')
param cpu string = '0.5'

@description('Memory allocation per replica.')
param memory string = '1Gi'

@description('Permitted redirect URI for the OAuth callback — must match the Entra app registration.')
param allowedRedirectUri string = 'https://claude.ai/api/mcp/auth_callback'

@description('Hostnames allowed for outbound downstream connections. Index 0 is always mcp.dev.azure.com; add more as needed.')
param egressAllowlist array = [
  'mcp.dev.azure.com'
]

@description('Custom public base URL (e.g. a custom domain). Leave empty to derive from the ACA environment default domain.')
param customPublicBaseUrl string = ''

@description('OBO target scope for Azure DevOps Remote MCP.')
param oboTargetScope string = '2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools'

@description('Identity to use when pulling the image from ACR. "system-environment" uses the ACA Environment\'s managed identity (typical when the ACR is shared across teams and only the platform team can grant AcrPull). "system" uses this app\'s own system-assigned identity (requires you to be Owner/User Access Administrator on the ACR so the Bicep can create the AcrPull role assignment).')
@allowed([
  'system-environment'
  'system'
])
param registryIdentityMode string = 'system-environment'

@description('How to source the OBO client secret. "KeyVault" (production-grade) references a secret stored in Key Vault — requires the app\'s system identity to have "Key Vault Secrets User" on the KV, AND for that RBAC to be propagated before the new revision starts (usually 1-2 min after the role assignment is created; race condition possible on first deploy). "Direct" (simpler, no race) takes the secret value as a @secure() parameter and stores it directly in the Container App secret — no KV dependency. Use Direct to unblock initial deployments; migrate to KeyVault once the platform team confirms the role assignment is in place.')
@allowed([
  'KeyVault'
  'Direct'
])
param secretSource string = 'KeyVault'

@description('OBO client secret value — required ONLY when secretSource = "Direct". Marked @secure() so it never appears in deployment logs or state. Leave empty when using KeyVault mode.')
@secure()
param oboClientSecretValue string = ''

// ---------------------------------------------------------------------------
// Variables — derived / hard-coded guardrails
// ---------------------------------------------------------------------------

// Existing resources (references only — not created by this template)
resource acaEnv 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: containerAppsEnvironmentName
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

// Key Vault is only resolved (and the role assignment created) when the
// secretSource is 'KeyVault'. In 'Direct' mode keyVaultName can be left as
// '<placeholder>' or any value — it's not dereferenced.
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = if (secretSource == 'KeyVault') {
  name: keyVaultName
}

// FQDN derivation: if customPublicBaseUrl is set, use it; otherwise derive
// from the ACA environment's defaultDomain.
var derivedFqdn = '${appName}.${acaEnv.properties.defaultDomain}'
var publicBaseUrl = empty(customPublicBaseUrl)
  ? 'https://${derivedFqdn}'
  : customPublicBaseUrl

// Authority — multi-cloud safe (uses Azure environment's login endpoint).
// In Azure public cloud this resolves to https://login.microsoftonline.com/.
#disable-next-line no-hardcoded-env-urls
var entraAuthority = '${environment().authentication.loginEndpoint}${entraTenantId}/v2.0'

// Full image reference. The repository name (between the registry host and
// the tag) is the imageRepository PARAMETER — NOT the Container App's name.
// Decoupled because the image is pushed once to ACR under a stable repo name
// (e.g. "entra-mcp-proxy") and reused across multiple app instances that may
// have any name ("aca-entra-mcp-proxy-devel", "aca-entra-mcp-proxy-prod", …).
var imageRef = '${acrName}.azurecr.io/${imageRepository}:${imageTag}'

// RBAC role definition IDs (built-in, tenant-wide constants)
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
// Key Vault Secrets User — built-in role.
// Reference: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security#key-vault-secrets-user
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

// Build the EgressAllowlist env vars dynamically from the array parameter.
// Each entry becomes Proxy__EgressAllowlist__N=<host>
var egressEnvVars = [for (host, i) in egressAllowlist: {
  name: 'Proxy__EgressAllowlist__${i}'
  value: host
}]

// ---------------------------------------------------------------------------
// Container App
// ---------------------------------------------------------------------------

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    environmentId: acaEnv.id
    configuration: {
      // Pull image using managed identity — no registry username/password.
      // 'system-environment' = use the ACA Environment's identity (default,
      // works when AcrPull on the shared ACR is granted at env level by the
      // platform team — typical for org-shared ACRs).
      // 'system' = use this app's own system-assigned identity (only when the
      // operator can grant AcrPull on the ACR themselves).
      registries: [
        {
          server: '${acrName}.azurecr.io'
          identity: registryIdentityMode
        }
      ]
      // The OBO client secret can be sourced either from Key Vault (production,
      // requires propagated RBAC) or stored directly as a @secure() parameter
      // value (simpler, no KV race). See `secretSource` parameter.
      secrets: secretSource == 'KeyVault' ? [
        {
          name: 'obo-client-secret'
          keyVaultUrl: '${keyVault.properties.vaultUri}secrets/${clientSecretSecretName}'
          identity: 'system'
        }
      ] : [
        {
          name: 'obo-client-secret'
          value: oboClientSecretValue
        }
      ]
      ingress: {
        external: true
        transport: 'http'
        allowInsecure: false       // HTTPS-only — hard guardrail
        targetPort: 80
        traffic: [
          {
            weight: 100
            latestRevision: true
          }
        ]
      }
    }
    template: {
      containers: [
        {
          name: appName
          image: imageRef
          resources: {
            cpu: json(cpu)
            memory: memory
          }
          // ---------------------------------------------------------------
          // Environment variables
          // Hard-coded guardrails cannot be weakened by optional parameters.
          // ---------------------------------------------------------------
          env: union(
            // --- Hard-coded guardrails ---
            [
              { name: 'ASPNETCORE_ENVIRONMENT',        value: 'Production' }        // locked
              { name: 'ASPNETCORE_URLS',               value: 'http://+:80' }       // Kestrel HTTP; ACA terminates TLS
              { name: 'EntraId__RequireHttpsMetadata',  value: 'true' }             // locked — Phase 3 N18 startup guard
              // Derived from tenantId parameter
              { name: 'EntraId__Authority',            value: entraAuthority }
              { name: 'EntraId__TenantId',             value: entraTenantId }
              { name: 'EntraId__ClientId',             value: entraClientId }
              // Proxy core
              { name: 'Proxy__PublicBaseUrl',          value: publicBaseUrl }
              { name: 'Proxy__AllowedRedirectUris__0', value: allowedRedirectUri }
              // Downstream server 0 — Azure DevOps Remote MCP
              { name: 'DownstreamServers__0__Name',       value: 'Azure DevOps' }
              { name: 'DownstreamServers__0__Prefix',     value: 'azdevops' }
              { name: 'DownstreamServers__0__BaseUrl',    value: 'https://mcp.dev.azure.com/${azureDevOpsOrganization}' }
              { name: 'DownstreamServers__0__AuthType',   value: 'OBOToken' }       // locked
              { name: 'DownstreamServers__0__Enabled',    value: 'true' }           // locked
              { name: 'DownstreamServers__0__OBO__TenantId',    value: entraTenantId }
              { name: 'DownstreamServers__0__OBO__ClientId',    value: entraClientId }
              // OBO client secret MUST come via secretRef — never a literal value
              {
                name: 'DownstreamServers__0__OBO__ClientSecret'
                secretRef: 'obo-client-secret'
              }
              { name: 'DownstreamServers__0__OBO__TargetScope', value: oboTargetScope }
              { name: 'DownstreamServers__0__TimeoutSeconds',   value: '60' }
            ],
            // --- Dynamic egress allowlist (index 0..N from parameter array) ---
            egressEnvVars
          )
          // -----------------------------------------------------------------
          // Health probes
          // -----------------------------------------------------------------
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/api/healthz'
                port: 80
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/api/readyz'
                port: 80
              }
              initialDelaySeconds: 5
              periodSeconds: 15
            }
            {
              type: 'Startup'
              httpGet: {
                path: '/api/healthz'
                port: 80
              }
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 12    // 12 × 5s = 60s for cold start
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-scale'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Role assignment: AcrPull — only created when registryIdentityMode = 'system'
// (i.e. this app pulls with its own identity). When using 'system-environment'
// the AcrPull role is assumed already granted to the ACA Environment's
// identity by the platform team — which is the typical pattern for shared
// org-wide ACRs the deploying user may not have Owner permissions on.
// ---------------------------------------------------------------------------

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (registryIdentityMode == 'system') {
  name: guid(acr.id, containerApp.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Role assignment: Key Vault Secrets User — lets the app read the client secret
// ---------------------------------------------------------------------------

resource kvSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (secretSource == 'KeyVault') {
  name: guid(keyVault.id, containerApp.id, kvSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

@description('FQDN of the deployed Container App ingress.')
output appFqdn string = containerApp.properties.configuration.ingress.fqdn

@description('Public base URL of the proxy (https://fqdn).')
output publicBaseUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'

@description('MCP endpoint URL — paste this into claude.ai Integrations.')
output mcpEndpointUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'

@description('OAuth discovery document URL (for troubleshooting).')
output oauthDiscoveryUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}/.well-known/openid-configuration'

@description('Health check URL.')
output healthzUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}/api/healthz'

@description('Operator next-steps message.')
output nextStepsMessage string = '=== DEPLOYMENT COMPLETE — NEXT STEPS ===\n\n1. VERIFY HEALTH\n   curl https://${containerApp.properties.configuration.ingress.fqdn}/api/healthz\n   Expected: HTTP 200 { "status": "Healthy" }\n\n2. UPDATE ENTRA APP REGISTRATION (if not already done)\n   In your Entra app registration, ensure the Web Redirect URI is EXACTLY:\n     https://claude.ai/api/mcp/auth_callback\n   (no trailing slash, no extra URIs)\n\n3. CONFIRM CLIENT SECRET IS IN KEY VAULT\n   The secret named "${clientSecretSecretName}" must exist in Key Vault "${keyVaultName}".\n   The Container App reads it via managed identity — no manual copy needed after rotation.\n\n4. CONNECT CLAUDE.AI\n   Go to claude.ai -> Settings -> Integrations -> Add integration\n   Set the MCP Server URL to:\n     https://${containerApp.properties.configuration.ingress.fqdn}\n   Users will authenticate with their Entra account on first use.\n\n5. RUN SANDBOX VALIDATION\n   Follow docs/sandbox-validation.md to verify end-to-end scenarios.\n'
