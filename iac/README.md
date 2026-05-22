# EntraMcpProxy — Infrastructure as Code (Azure Container Apps)

This directory contains everything needed to deploy **EntraMcpProxy** to Azure Container Apps end-to-end: an idempotent Entra app-registration setup script, a minimum-input Bicep template, and operator-facing deploy scripts in both bash and PowerShell.

The deploy path is intentionally short: **provision the Entra app → fill a parameter file → run the deploy script**. Each step is documented below.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Azure CLI** ≥ 2.60 | `az --version`. <https://learn.microsoft.com/cli/azure/install-azure-cli> |
| **Bicep CLI** | Installed automatically via `az bicep install` if absent. |
| **`az login`** | Authenticate to the correct subscription **and** tenant. The Entra app provisioning step requires Cloud Application Administrator (or higher) to grant admin consent. |
| **Existing ACA environment** | `az containerapp env create …` in the same resource group as the deploy. |
| **ACR with the proxy image pushed** | `<acr>.azurecr.io/entra-mcp-proxy:1.0.0` must exist before deploy. |

---

## End-to-end deploy (≈ 10 minutes)

### Step 1 — Provision the Entra app registration

```bash
# bash
bash iac/setup-entra-app.sh

# PowerShell
pwsh iac/setup-entra-app.ps1
```

This single command creates the app, exposes `user_impersonation`, requests the `Ado.Mcp.Tools` delegated permission on Azure DevOps Remote MCP, grants admin consent, configures the redirect URI for claude.ai, and mints a 2-year client secret. **The flag that makes the included test script work — `isFallbackPublicClient: true` — is set here too**; see [the change log](../docs/changes/2026-05-22-stabilization.md) for the AADSTS7000218 story behind that.

When it finishes you get a four-line block to paste straight into the parameter file:

```bicep
param entraTenantId        = 'xxxxxxxx-xxxx-…'
param entraClientId        = 'yyyyyyyy-yyyy-…'
param secretSource         = 'Direct'
param oboClientSecretValue = '<one-time-printed-secret>'
```

> **The client secret is shown ONCE.** Save it to a password manager. If you lose it, re-run the script — `--append` adds a new secret without invalidating the old one.

### Step 2 — Fill the parameter file

```bash
cp iac/parameters.example.bicepparam iac/parameters.bicepparam
# Open in your editor; paste the block from step 1; fill the rest.
```

`parameters.bicepparam` is already in `.gitignore`. Five values you need:

| Param | Where from |
|---|---|
| `containerAppsEnvironmentName` | The existing ACA environment name |
| `acrName` | The ACR holding the proxy image (no `.azurecr.io`) |
| `azureDevOpsOrganization` | The `{org}` from `https://dev.azure.com/{org}` |
| `entraTenantId` / `entraClientId` | Printed by `setup-entra-app.sh` |
| `oboClientSecretValue` | Printed by `setup-entra-app.sh` |

### Step 3 — Deploy

```bash
# bash
bash iac/deploy.sh --resource-group <your-rg>

# PowerShell
pwsh iac/deploy.ps1 -ResourceGroup <your-rg>
```

The script runs `az deployment group what-if` first and asks for confirmation before applying any change. It is **idempotent** — re-running against an existing app updates it in place.

The deployment outputs include:

- `mcpEndpointUrl` — paste this URL **with `/mcp` appended** into claude.ai
- `oauthDiscoveryUrl` — the `/.well-known/openid-configuration` document (useful for troubleshooting)
- `nextStepsMessage` — the post-deploy checklist

### Step 4 — Connect claude.ai

1. `claude.ai → Settings → Integrations → Add integration`
2. **Integration URL** = `<mcpEndpointUrl>/mcp`
3. **Client ID** = the `entraClientId` from your parameter file
4. **Client Secret** = the `oboClientSecretValue` from your parameter file
5. Save → complete the OAuth flow with a user in your tenant. The first authenticated `tools/list` lazy-discovers Azure DevOps tools.

### Step 5 — Smoke-test from the CLI (optional but recommended)

```bash
bash iac/test/test-mcp.sh \
  --tenant-id     <entraTenantId> \
  --client-id     <entraClientId> \
  --client-secret <oboClientSecretValue> \
  --proxy-url     <mcpEndpointUrl-without-/mcp>
```

The script runs every MCP protocol step: pre-flight, device-code OAuth, `initialize`, `tools/list`, `tools/call`, session delete. See `iac/test/README.md` for details on what each step asserts.

---

## What gets deployed

| Resource | Type | Notes |
|---|---|---|
| `entra-mcp-proxy` (or `appName`) | `Microsoft.App/containerApps` | Container App with system-assigned managed identity |
| `AcrPull` role assignment on ACR | `Microsoft.Authorization/roleAssignments` | Only when `registryIdentityMode = 'system'`. Lets the app pull its own image without a registry password. |
| `Key Vault Secrets User` role assignment on KV | `Microsoft.Authorization/roleAssignments` | Only when `secretSource = 'KeyVault'`. Lets the app read the client secret at runtime. |

### Hard-coded guardrails

These values are locked in the template and cannot be weakened by parameters:

| Setting | Value | Why |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | `Production` | Triggers production-mode security checks (Phase 3 N18 startup guard, etc.) |
| `ASPNETCORE_URLS` | `http://+:8080` | Non-root port; ACA terminates TLS at ingress |
| `EntraId__RequireHttpsMetadata` | `true` | Startup guard refuses `false` in Production |
| `DownstreamServers__0__AuthType` | `OBOToken` | Identity delegation cannot be disabled |
| Ingress `allowInsecure` | `false` | HTTPS-only external ingress |
| Secret env vars | `secretRef` | Never embedded as a literal value in the template |

---

## Secret source: Direct vs Key Vault

`secretSource = 'Direct'` (the new default) stores the OBO client secret directly in the Container App's secret store. The value passes through Bicep as a `@secure()` parameter that Azure scrubs from deployment logs and state. No additional infrastructure required.

`secretSource = 'KeyVault'` keeps the secret in Key Vault; the Container App reads it at runtime via `Key Vault Secrets User` granted to its managed identity. This is the right choice when you have:

- A hardened KV rotation pipeline (the proxy picks up new secret versions automatically after the ACA secret is refreshed)
- Separation of duties — only the platform team can write to KV; app operators never see the value

**KV mode has a known race**: the role assignment is created in the same deployment as the Container App, and RBAC propagation can take 1-2 minutes. The first revision may fail before propagation completes. ACA marks the revision as Failed and keeps serving the previous one. Re-run the deploy — it is idempotent — and the second pass succeeds.

For most environments, **Direct mode is what you want**.

---

## Customisation

All optional parameters are documented in [`parameters.example.bicepparam`](parameters.example.bicepparam). Most-touched:

| Parameter | Default | When to change |
|---|---|---|
| `imageTag` | `1.0.0` | Updating to a newer release |
| `minReplicas` | `1` | Set to `0` if cost matters more than cold-start latency |
| `maxReplicas` | `3` | Increase for high-traffic environments |
| `egressAllowlist` | `['mcp.dev.azure.com']` | Add more downstream MCP hosts |
| `customPublicBaseUrl` | derived from ACA | Set if you configured a custom domain |
| `secretSource` | `Direct` | Switch to `KeyVault` once your KV rotation pipeline is hardened |

---

## Cleanup

```bash
# Remove the Container App + its role assignments
az deployment group delete --resource-group <rg> --name <deployment-name>

# Or delete the entire resource group (destructive — removes everything in it)
az group delete --name <rg> --yes
```

The Entra app registration is **not** removed by either command. If you need to clean it up too:

```bash
az ad app delete --id <entraClientId>
```

---

## Troubleshooting

### `setup-entra-app.sh` fails granting admin consent

Your signed-in account lacks Cloud Application Administrator. Either run as an admin, or hand the printed command to one:

```bash
az ad app permission admin-consent --id <entraClientId>
```

### Deployment fails with "The identity does not have permission to access Key Vault"

You are in `secretSource = 'KeyVault'` mode and hit the RBAC propagation race. Re-run the same deploy command — the role assignment from the first attempt will have propagated by the second.

### Container App starts but `/api/healthz` returns 5xx

Check container logs:

```bash
az containerapp logs show --name entra-mcp-proxy --resource-group <rg> --tail 100
```

Most common causes:

- Wrong `entraTenantId` GUID → the OIDC discovery doc fetch fails at startup
- Wrong `oboClientSecretValue` → no startup error, but `tools/list` fails with `AADSTS7000215` ("invalid client secret") on the first authenticated request
- KV mode + secret name mismatch → revision fails immediately

### Image pull fails

Verify the AcrPull role assignment exists:

```bash
az role assignment list --scope $(az acr show --name <acr-name> --query id -o tsv) --role AcrPull
```

If absent, the role assignment may have failed due to a race. Re-run the deployment.

### `tools/list` returns zero tools

You are running an image built before commit `2c6035b` (lazy OBO discovery). Rebuild and redeploy — the fix lets background discovery skip OBO downstreams whose `DiscoveryScope` is unset, and triggers lazy discovery on the first authenticated `list_tools` instead. See [the change log](../docs/changes/2026-05-22-stabilization.md) for the full story.
