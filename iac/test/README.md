# EntraMcpProxy — End-to-End Smoke Test

Validates the complete MCP proxy stack in a deployed environment without needing claude.ai. A single command authenticates a real user via Entra and exercises every protocol layer.

## Purpose

The smoke test proves that:

1. The proxy is reachable and its OAuth discovery document is correct
2. Entra will issue a real access token for the proxy's audience (`api://<client-id>`)
3. The JWT validation, OBO exchange, and downstream call all succeed end-to-end
4. The MCP transport flow (initialize → tools/list → tools/call, plus optional session delete) works correctly
5. Security controls are active: provenance wrapping (`<downstream-content>`) and tool namespacing (`azdevops__*`) are present in responses

### Why Device Code flow

The proxy's `/authorize` endpoint only allows `redirect_uri = https://claude.ai/api/mcp/auth_callback`. Device Code flow goes **directly to Entra** (bypassing the proxy's OAuth facade), so no redirect is needed. The token is issued with the same claims (`aud=api://<client-id>`, `scp=user_impersonation`) as one obtained via claude.ai — the proxy validates it identically. MFA and Conditional Access policies are handled by Entra natively.

## Prerequisites

- The proxy must be deployed and the container app must be running (`/api/healthz` returns 200)
- The Entra app registration must be fully configured — see the [operations runbook app-reg checklist](../../docs/operations.md)
- In particular, the app registration must:
  - Expose a `user_impersonation` API scope under `api://<client-id>`
  - Have admin consent granted for the `Ado.Mcp.Tools` delegated permission
  - Allow public client flows (required for Device Code)

**PowerShell script:** Windows PowerShell 5.1 or PowerShell 7+. No extra modules needed.

**Bash script:** `curl` and `jq` must be installed. Works on Linux and macOS.

## Usage

### PowerShell

```powershell
# Interactive — lists tools, prompts to pick one, calls it with no args
.\test-mcp.ps1 `
    -TenantId  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx `
    -ClientId  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy `
    -ProxyUrl  https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io

# Specific tool with arguments
.\test-mcp.ps1 `
    -TenantId  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx `
    -ClientId  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy `
    -ProxyUrl  https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io `
    -ToolName  azdevops__list_projects `
    -ToolArgs  '{}'

# Non-interactive CI run (calls the first available tool, no prompts)
.\test-mcp.ps1 `
    -TenantId  $env:ENTRA_TENANT_ID `
    -ClientId  $env:ENTRA_CLIENT_ID `
    -ProxyUrl  $env:PROXY_URL
```

### Bash

```bash
# Make executable on first run
chmod +x iac/test/test-mcp.sh

# Interactive
./iac/test/test-mcp.sh \
    --tenant-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
    --client-id yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy \
    --proxy-url https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io

# Specific tool with arguments
./iac/test/test-mcp.sh \
    --tenant-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
    --client-id yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy \
    --proxy-url https://aca-entra-mcp-proxy-devel.whitemoss-f4f610a7.northeurope.azurecontainerapps.io \
    --tool-name azdevops__list_projects \
    --tool-args '{}'
```

## What each step proves

| Step | What it validates | Security control |
|------|-------------------|-----------------|
| 1. Pre-flight: `/api/healthz` | Proxy process is alive; liveness check works | Operational baseline |
| 1. Pre-flight: `/.well-known/openid-configuration` | OAuth discovery doc is well-formed; correct audience scope advertised | RFC 8414 / MCP OAuth discovery |
| 2. Device Code auth | Entra will issue a token for `api://<client-id>/user_impersonation`; MFA and Conditional Access work | Real Entra authentication |
| 3. MCP initialize | JWT signature/issuer/audience validation passes; OBO exchange succeeds; stateful or stateless MCP transport is accepted | N13, L17: JWT validation; Phase 7: OBO |
| 4. `notifications/initialized` | MCP spec compliance (client must send this after initialize) | MCP protocol correctness |
| 5. `tools/list` | Downstream connection is live; tools are namespaced (`azdevops__*`); description provenance prefix present | N5/N6: tool poisoning defense (Phase 9) |
| 6. `tools/call` | Full call path works end-to-end; OBO token reaches downstream; `<downstream-content>` wrapping present | N11: tool result provenance (Phase 10) |
| 7. DELETE session | Stateful sessions terminate correctly; skipped for stateless transport | MCP spec compliance |

## Troubleshooting

### `AADSTS65001` — admin consent required

The `Ado.Mcp.Tools` (or equivalent) delegated permission needs tenant-wide admin consent. A Global Admin must visit:

```
https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=<client-id>
```

Or grant consent via the Azure portal: App registrations → your app → API permissions → Grant admin consent.

### `401 Unauthorized` from proxy

The proxy rejected the access token. Common causes:

- **Audience claim wrong**: the `aud` claim in the token must be `api://<client-id>` or `<client-id>`. Verify `-ClientId` / `--client-id` matches the app registration exactly.
- **Issuer mismatch**: v1.0 tokens use `sts.windows.net/<tenant-id>/`; v2.0 use `login.microsoftonline.com/<tenant-id>/v2.0`. Both are accepted by the proxy — if you see an issuer error, check `EntraId:TenantId` in the proxy config matches `-TenantId` / `--tenant-id`.
- **Token expired**: access tokens expire (typically 1 hour). Re-run the script to get a fresh token.
- **Wrong scope requested**: the token must include `user_impersonation` in the `scp` claim. Check the JWT claims printed in Step 2.

### `Mcp-Session-Id` header missing from initialize response

This is expected for current deployments: the proxy runs MCP HTTP transport in stateless mode so Azure Container Apps load balancing, restarts, and revision changes do not invalidate replica-local sessions. The smoke scripts only send `Mcp-Session-Id` when a stateful deployment returns one.

### Tool call returns `isError: true` with a permissions message

The proxy and OBO exchange worked correctly, but the user does not have access to the requested Azure DevOps resource. This is an ADO authorization issue, not a proxy bug. Check the user's ADO organization membership and project access.

### `AADSTS50020` — user account from external identity provider

The user signing in is a guest in the tenant. Guest accounts may not be able to consent to or use delegated API permissions depending on tenant policy. Use an account that is a member of the tenant.

### Tool list is empty

The proxy is running but no downstream MCP servers are connected. Check the proxy configuration (`DownstreamServers` in `appsettings.json` / environment variables) and the proxy logs for `ToolAggregatorService` errors.

### `curl: (60)` SSL certificate error (bash script)

The proxy is using a self-signed or untrusted certificate. For testing only, you can add `-k` to the curl calls in the script. For production, ensure the container app has a valid TLS certificate.
