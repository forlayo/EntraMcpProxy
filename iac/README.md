# EntraMcpProxy — Infrastructure as Code (Azure Container Apps)

This directory contains a minimal-input Bicep template that deploys **EntraMcpProxy** to Azure Container Apps. You supply six deployment-specific values; everything else is derived or has a sensible default.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Azure CLI** ≥ 2.60 | `az --version`. Install: <https://learn.microsoft.com/cli/azure/install-azure-cli> |
| **Bicep CLI** | Installed automatically via `az bicep install` if absent. |
| **`az login`** | Must be authenticated to the correct subscription and tenant. |
| **Existing ACA environment** | `az containerapp env create ...` in the same RG. |
| **ACR with image pushed** | `acrsharedservicesglobal01.azurecr.io/entra-mcp-proxy:1.0.0` must exist. |
| **Existing Key Vault** | Must hold the Entra client secret (see *Before* section below). |
| **Entra app registration** | Must be configured as described in [docs/operations.md](../docs/operations.md). |

---

## 5-Minute Deploy

```bash
# 1. Copy and edit the parameters file (tracked as .gitignore'd)
cp iac/parameters.example.bicepparam iac/parameters.bicepparam
# Edit iac/parameters.bicepparam — fill in the 6 required values.

# 2. Deploy (PowerShell)
pwsh iac/deploy.ps1 -ResourceGroup rg-entra-mcp-prod

# 2. Deploy (bash / macOS / Linux)
bash iac/deploy.sh --resource-group rg-entra-mcp-prod
```

The script runs a **what-if diff** first and asks for confirmation before making any changes.

---

## What Gets Deployed

The Bicep template creates three resources in your resource group:

| Resource | Type | Notes |
|---|---|---|
| `entra-mcp-proxy` | `Microsoft.App/containerApps` | The Container App with system-assigned managed identity |
| Role assignment | `Microsoft.Authorization/roleAssignments` (on ACR) | `AcrPull` — lets the app pull its own image without a registry password |
| Role assignment | `Microsoft.Authorization/roleAssignments` (on Key Vault) | `Key Vault Secrets User` — lets the app read the client secret at runtime |

### Hard-coded guardrails

These values are locked in the template. They cannot be weakened by optional parameters:

| Setting | Value | Why |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | `Production` | Triggers all production-mode security checks in the proxy |
| `ASPNETCORE_URLS` | `http://+:8080` | Kestrel listens HTTP on a non-privileged port; ACA terminates TLS at the ingress |
| `EntraId__RequireHttpsMetadata` | `true` | Phase 3 startup guard refuses `false` in Production |
| `DownstreamServers__0__AuthType` | `OBOToken` | Identity delegation cannot be disabled |
| Ingress `allowInsecure` | `false` | HTTPS-only external ingress |
| `OBO__ClientSecret` | `secretRef` from Key Vault | Secret never stored as a literal value |

---

## What You Must Do BEFORE Running This

### 1. Store the client secret in Key Vault

```bash
az keyvault secret set \
  --vault-name <your-keyvault-name> \
  --name entra-mcp-proxy-client-secret \
  --value "<paste-client-secret-here>"
```

The Container App reads this at startup via its managed identity. After the role assignment is deployed, the app has `Key Vault Secrets User` access.

### 2. Configure the Entra app registration

See [docs/operations.md](../docs/operations.md) and the README's **Entra ID Setup** section. Required:

- App registered with `api://{client-id}/user_impersonation` scope exposed
- Redirect URI: `https://claude.ai/api/mcp/auth_callback` (and no other)
- Delegated permission `Ado.Mcp.Tools` on resource `2a72489c-aab2-4b65-b93a-a91edccf33b8`, with admin consent granted
- "Allow public client flows" disabled

### 3. Push the image to ACR

```bash
az acr login --name <your-acr-name>
docker tag entra-mcp-proxy:1.0.0 <your-acr-name>.azurecr.io/entra-mcp-proxy:1.0.0
docker push <your-acr-name>.azurecr.io/entra-mcp-proxy:1.0.0
```

### 4. Ensure the ACA environment exists

```bash
az containerapp env create \
  --name <your-aca-environment-name> \
  --resource-group <your-rg> \
  --location eastus
```

---

## What You Must Do AFTER Running This

### 1. Verify health

```bash
curl https://<your-app-fqdn>/api/healthz
# Expected: HTTP 200  { "status": "Healthy", ... }
```

### 2. Configure claude.ai

1. Open **claude.ai → Settings → Integrations → Add integration**
2. Set **MCP Server URL** to the `mcpEndpointUrl` output from the deploy script
3. Complete the OAuth flow — users authenticate with their Entra account

### 3. Run sandbox validation

Follow [docs/sandbox-validation.md](../docs/sandbox-validation.md) to confirm all compatibility scenarios and security probes pass before engaging production users.

---

## Customization

All optional parameters are documented with comments in [`parameters.example.bicepparam`](parameters.example.bicepparam). Key options:

| Parameter | Default | When to change |
|---|---|---|
| `imageTag` | `1.0.0` | Updating to a newer release |
| `minReplicas` | `1` | Set to `0` if cost matters more than cold-start latency |
| `maxReplicas` | `3` | Increase for high-traffic environments |
| `egressAllowlist` | `['mcp.dev.azure.com']` | Add more downstream MCP hosts |
| `customPublicBaseUrl` | `` (derive from ACA) | Set if you configured a custom domain |
| `allowedRedirectUri` | claude.ai callback | Only change for non-production testing |

---

## Cleanup

To remove the deployed resources:

```bash
# Remove the Container App and its role assignments
az deployment group delete --resource-group <rg> --name <deployment-name>

# Or delete the entire resource group (destructive — removes everything in it)
az group delete --name <rg> --yes
```

---

## Troubleshooting

### Deployment fails with "The identity does not have permission to access Key Vault"

The role assignment is created in the same deployment as the Container App. Azure RBAC propagation can take up to 2 minutes. Re-run the deploy script — it is idempotent.

### Container App starts but /api/healthz returns 500

Check the container logs:

```bash
az containerapp logs show \
  --name entra-mcp-proxy \
  --resource-group <rg> \
  --tail 100
```

Common causes:
- `EntraId__RequireHttpsMetadata=true` with a misconfigured authority (check `entraTenantId` GUID is correct)
- Key Vault secret not found — verify `clientSecretSecretName` matches the name you stored

### Image pull fails

Verify the `AcrPull` role assignment exists:

```bash
az role assignment list \
  --scope $(az acr show --name <acr-name> --query id -o tsv) \
  --role AcrPull
```

If absent, the role assignment may have failed due to a race condition. Re-run the deployment.
