# EntraMcpProxy

An MCP (Model Context Protocol) gateway that bridges **Claude Web** (`claude.ai`) to **Azure DevOps** and any other MCP-compatible backend — using Entra ID (Azure AD) for authentication and the OAuth 2.0 On-Behalf-Of flow for identity delegation.

```
Claude Web (claude.ai)
    │
    │  OAuth2 PKCE → /authorize → Entra ID
    │  Bearer token (user's identity)
    ▼
EntraMcpProxy  (.NET 10)
    │  ┌──────────────────────────────────────┐
    │  │  Aggregated tool namespace:          │
    │  │  azdevops__* → AzDO Remote MCP       │
    │  │  internal__* → Internal MCP Server   │
    │  │  other__*    → Any MCP backend       │
    │  └──────────────────────────────────────┘
    │
    │  On-Behalf-Of (OBO) → user's Entra ID token
    ▼
Azure DevOps Remote MCP  (mcp.dev.azure.com/{org})
    ▼
Azure DevOps APIs
```

---

## Why This Exists

Microsoft released the [Azure DevOps Remote MCP Server](https://github.com/microsoft/azure-devops-mcp) (`mcp.dev.azure.com/{org}`) in early 2025, exposing Azure Boards, Repos, Pipelines, and Test Plans as MCP tools. It works well with Claude Code (the developer CLI) — but **not with Claude Web**, which is the interface most accessible to non-technical users (Product Owners, Engineering Managers, QA leads, Finance).

The root cause: **Entra ID does not support RFC 7591 Dynamic Client Registration**. The MCP specification requires that clients like Claude Web dynamically register as OAuth clients when they encounter a new MCP server. Without a pre-registered `client_id`, the authorization flow cannot start. Microsoft has [publicly acknowledged this constraint](https://github.com/microsoft/azure-devops-mcp/issues/1077).

This proxy solves that by acting as an **OAuth Authorization Server facade** in front of Entra ID, and as an **MCP aggregator** that routes tool calls to downstream servers using the authenticated user's identity.

---

## Features

- **OAuth AS facade** — exposes `/authorize`, `/token`, and `/.well-known/openid-configuration` so Claude Web can complete the standard OAuth 2.0 + PKCE flow
- **RFC 9728 compliant** — `/.well-known/oauth-protected-resource` points Claude Web to the proxy as the authorization server
- **On-Behalf-Of (OBO) identity delegation** — every downstream call uses the authenticated user's real identity, never a shared service account
- **Tool aggregation with namespacing** — tools from multiple MCP backends are merged under a single endpoint, prefixed by server name (`azdevops__create_work_item`, `internal__list_projects`, etc.)
- **Background tool discovery** — connects to all configured downstream servers at startup and refreshes tool lists on a configurable interval
- **Multiple auth modes for downstream servers** — supports OBO (for Azure DevOps), API key, and Entra ID client credentials
- **Kubernetes-ready** — handles `X-Forwarded-Proto`/`X-Forwarded-Host` from ingress TLS termination
- **Docker image included**

---

## Quick Start

### 1. Configure Entra ID

See the [Entra ID Setup](#entra-id-setup) section below for the full one-time configuration. You will need:

- An App Registration with `api://{client-id}/user_impersonation` scope exposed
- A client secret
- Delegated permission `Ado.Mcp.Tools` on resource `2a72489c-aab2-4b65-b93a-a91edccf33b8` (Azure DevOps Remote MCP), with admin consent granted

### 2. Configure the proxy

Edit `appsettings.json` (or use environment variables / Kubernetes secrets):

```json
{
  "EntraId": {
    "Authority": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "TenantId": "{tenant-id}",
    "ClientId": "{client-id}"
  },
  "DownstreamServers": [
    {
      "Name": "Azure DevOps",
      "Prefix": "azdevops",
      "AuthType": "OBOToken",
      "BaseUrl": "https://mcp.dev.azure.com/{your-organization}",
      "OBO": {
        "TenantId": "{tenant-id}",
        "ClientId": "{client-id}",
        "ClientSecret": "{client-secret}",
        "TargetScope": "2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools"
      },
      "Enabled": true,
      "TimeoutSeconds": 60
    }
  ],
  "Proxy": {
    "RefreshIntervalMinutes": 5
  }
}
```

### 3. Run

```bash
dotnet run
# or
docker build -t entra-mcp-proxy .
docker run -p 8080:80 --env-file .env entra-mcp-proxy
```

### 4. Connect Claude Web

In Claude Web → Settings → Integrations → Add MCP Server:

| Field | Value |
|---|---|
| MCP Server URL | `https://{your-proxy-domain}` |
| `client_id` | Application (client) ID from Entra ID |
| `client_secret` | Client secret created in Entra ID |

Users authenticate once with their Entra ID account (SSO). All Azure DevOps actions are performed on behalf of the authenticated user.

---

## Architecture

### OAuth Flow

Claude Web does not discover the authorization server from `/.well-known/oauth-protected-resource` — it constructs `{mcp_url}/authorize` directly. The proxy acts as an AS facade, redirecting to Entra ID:

```
Claude Web → GET {proxy}/authorize?client_id=...&code_challenge=...
Proxy      → 302 → login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
Entra ID   → redirect back to claude.ai with code
Claude Web → POST {proxy}/token
Proxy      → forward → login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Claude Web → Bearer token in Authorization header on every MCP request
```

### Identity Delegation (OBO)

When Claude Web calls an MCP tool, the proxy:

1. Validates the incoming Bearer token (Entra ID JWT)
2. Exchanges it for a downstream token via OAuth 2.0 On-Behalf-Of (RFC 8693)
3. Forwards the tool call to the appropriate downstream MCP server using that token

This means:
- **Permissions are fully respected** — if the user has no access to a repo, they cannot read it through Claude either
- **Audit logs show real users** — no actions attributed to a service account
- **No privilege escalation** — the proxy cannot grant more access than the user already has

### Tool Namespacing

Each downstream server is assigned a `Prefix` in configuration. All tools from that server are exposed as `{prefix}__{tool_name}`:

| Downstream Server | Prefix | Example Tool |
|---|---|---|
| Azure DevOps Remote MCP | `azdevops` | `azdevops__create_work_item` |
| Internal MCP Server | `internal` | `internal__list_projects` |

Prefixes prevent name collisions across backends. Adding a new MCP backend is a single configuration entry — no new deployment.

### Project Structure

```
EntraMcpProxy/
├── Program.cs                        # App bootstrap, OAuth facade endpoints, MCP server setup
├── Auth/
│   ├── EntraIdOBOHandler.cs          # OBO token exchange (RFC 8693)
│   └── EntraIdTokenHandler.cs        # Token validation handler
├── Configuration/
│   └── DownstreamServerConfig.cs     # Config model for downstream servers
├── Infrastructure/
│   └── GlobalExceptionHandler.cs     # Unhandled exception middleware
└── Services/
    ├── ToolRegistry.cs               # In-memory registry of namespaced tools
    ├── DownstreamClientManager.cs    # Manages persistent MCP client connections
    ├── ProxyToolHandler.cs           # Routes list/call requests to correct downstream
    └── ToolAggregatorService.cs      # Background service for tool discovery + refresh
```

---

## Configuration Reference

### `EntraId`

All keys are **required**. The application will throw on startup if any are missing.

| Key | Description |
|---|---|
| `Authority` | Entra ID OIDC authority, e.g. `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `TenantId` | Directory (tenant) ID |
| `ClientId` | Application (client) ID |
| `RequireHttpsMetadata` | Default `true`. Set to `false` for local development only. |

### `DownstreamServers[]`

| Key | Description |
|---|---|
| `Name` | Human-readable name for logs |
| `Prefix` | Tool namespace prefix (no spaces, lowercase recommended) |
| `BaseUrl` | MCP server base URL |
| `AuthType` | `OBOToken`, `ApiKey`, or `EntraId` |
| `Enabled` | `true` / `false` |
| `TimeoutSeconds` | HTTP timeout for downstream calls |
| `OBO.TenantId` | Tenant for OBO exchange |
| `OBO.ClientId` | Client ID used in OBO exchange |
| `OBO.ClientSecret` | Client secret used in OBO exchange |
| `OBO.TargetScope` | Downstream resource scope, e.g. `{resource-id}/{scope}` |
| `ApiKey` | API key (when `AuthType` is `ApiKey`) |

### `Proxy`

| Key | Description | Default |
|---|---|---|
| `RefreshIntervalMinutes` | How often the background service rediscovers tools from all downstream servers | `5` |

---

## Entra ID Setup

One-time configuration in the Azure portal (or Azure CLI / Terraform).

### Step 1 — Register the Application

In **Microsoft Entra ID → App registrations**, create a new registration:

- **Supported account types:** Single tenant
- **Redirect URI:** Web platform — `https://claude.ai/api/mcp/auth_callback`

Note the **Application (client) ID** and **Directory (tenant) ID**.

### Step 2 — Create a Client Secret

Under **Certificates & secrets → New client secret**. Copy the value immediately.

This secret is used both by the proxy (to perform OBO exchanges) and by Claude Web (as `client_secret` in the token request).

### Step 3 — Expose an API Scope

Under **Expose an API**:

1. Set **Application ID URI** to `api://{client-id}`
2. Add a scope named `user_impersonation`
   - Who can consent: Admins and users

### Step 4 — Grant Permission for Azure DevOps Remote MCP

Under **API permissions → Add a permission → APIs my organization uses**, find:

- **Resource ID:** `2a72489c-aab2-4b65-b93a-a91edccf33b8`
- **Permission:** `Ado.Mcp.Tools` (delegated)

Click **Grant admin consent**. Required once. Without this, OBO exchange fails with `AADSTS65001`.

### Step 5 — Add Users to Azure DevOps

Users must exist in the Azure DevOps organization at `https://dev.azure.com/{org}/_settings/users`.

### Summary

| Configuration Key | Value |
|---|---|
| `EntraId:TenantId` | Directory (tenant) ID |
| `EntraId:ClientId` | Application (client) ID |
| `OBO:ClientSecret` | Client secret from Step 2 |
| `OBO:TargetScope` | `2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools` |
| Claude Web `client_id` | Application (client) ID |
| Claude Web `client_secret` | Client secret from Step 2 |
| Claude Web MCP URL | `https://{your-proxy-domain}` |

---

## Deployment

The project ships a multi-stage `Dockerfile` targeting `mcr.microsoft.com/dotnet/aspnet:10.0`.

### Docker

```bash
docker build -t entra-mcp-proxy .
docker run -p 8080:80 \
  -e EntraId__Authority="https://login.microsoftonline.com/{tenant}/v2.0" \
  -e EntraId__TenantId="{tenant}" \
  -e EntraId__ClientId="{client-id}" \
  entra-mcp-proxy
```

### Kubernetes / AKS

When deployed behind a Kubernetes ingress that terminates TLS, the proxy automatically trusts `X-Forwarded-Proto` and `X-Forwarded-Host` headers so that OAuth endpoints advertise correct `https://` URLs.

No additional ingress annotation is required — the forwarded header handling is configured unconditionally in `Program.cs`.

### Health Check

```
GET /api/healthz
→ 200 { "status": "Healthy", "timestamp": "..." }
```

---

## Known Technical Challenges

### JWT Issuer Mismatch (v1.0 tokens from v2.0 endpoint)

Access tokens for custom API scopes (`api://...`) are issued in **v1.0 format** — `iss: https://sts.windows.net/{tenant}/` — even when obtained via the v2.0 OIDC endpoint. The proxy configures `ValidIssuers` explicitly for both formats to avoid silent 401s:

```csharp
options.TokenValidationParameters.ValidIssuers = new[]
{
    $"https://sts.windows.net/{tenantId}/",
    $"https://login.microsoftonline.com/{tenantId}/v2.0",
    $"https://login.microsoftonline.com/{tenantId}/",
};
```

### RFC 8707 Resource Indicator Rejection (AADSTS9010010)

An earlier design pointed `authorization_servers` in the protected resource metadata directly to Entra ID. Claude Web followed RFC 8707 and included `resource={proxy_url}` in the Entra ID authorization request — which Entra ID rejected because the URL didn't match the registered App ID URI (`api://{clientId}`).

The proxy must remain the authorization server visible to Claude Web. The AS facade is not a workaround — it is the required architecture.

---

## Roadmap / Future State

Microsoft is actively working to close the Entra ID dynamic client registration gap ([issue #1077](https://github.com/microsoft/azure-devops-mcp/issues/1077)). When they do:

- The OAuth AS facade (`/authorize`, `/token`) can be removed
- The proxy can be repurposed as a **pure MCP aggregator** with OBO identity delegation
- No changes to downstream server configuration or tool namespacing

---

## References

- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [Azure DevOps Remote MCP Server](https://github.com/microsoft/azure-devops-mcp)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8693 — OAuth 2.0 Token Exchange (On-Behalf-Of)](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 7636 — PKCE for OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [Model Context Protocol](https://modelcontextprotocol.io)
