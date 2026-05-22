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
- **On-Behalf-Of (OBO) identity delegation** — tool calls use the authenticated user's Entra token; see [Identity Delegation](#identity-delegation) for the full picture
- **Tool aggregation with namespacing** — tools from multiple MCP backends are merged under a single endpoint, prefixed by server name (`azdevops__create_work_item`, `internal__list_projects`, etc.)
- **Background tool discovery** — connects to all configured downstream servers at startup and refreshes tool lists on a configurable interval
- **Multiple auth modes for downstream servers** — supports OBO (for Azure DevOps), API key, and Entra ID client credentials
- **Kubernetes-ready** — external URLs derived from `Proxy:PublicBaseUrl`; no dependency on forwarded headers
- **Docker image included**

---

## Quick Start

### 1. Configure Entra ID

See the [Entra ID Setup](#entra-id-setup) section below for the full one-time configuration. You will need:

- An App Registration with `api://{client-id}/user_impersonation` scope exposed
- A client secret
- Delegated permission `Ado.Mcp.Tools` on resource `2a72489c-aab2-4b65-b93a-a91edccf33b8` (Azure DevOps Remote MCP), with admin consent granted

### 2. Configure the proxy

All settings can be supplied via `appsettings.json` OR environment variables. **Secrets MUST come from environment variables, Kubernetes Secrets, or Azure Key Vault** — never from `appsettings.json`.

ASP.NET Core's configuration provider chain maps env vars to section paths via double-underscore separators:

| Setting                                  | Env variable                              |
|------------------------------------------|-------------------------------------------|
| `EntraId:TenantId`                       | `EntraId__TenantId`                       |
| `EntraId:ClientId`                       | `EntraId__ClientId`                       |
| `EntraId:Authority`                      | `EntraId__Authority`                      |
| `Proxy:PublicBaseUrl`                    | `Proxy__PublicBaseUrl`                    |
| `Proxy:AllowedRedirectUris:0`            | `Proxy__AllowedRedirectUris__0`           |
| `Proxy:EgressAllowlist:0`                | `Proxy__EgressAllowlist__0`               |
| `DownstreamServers:0:OBO:ClientSecret`   | `DownstreamServers__0__OBO__ClientSecret` |

For Azure Key Vault, use the
[Azure.Extensions.AspNetCore.Configuration.Secrets](https://learn.microsoft.com/aspnet/core/security/key-vault-configuration)
provider; it auto-maps Key Vault secret names of the form
`DownstreamServers--0--OBO--ClientSecret` onto the config path.

For Kubernetes, use a Secret resource mounted as env vars:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: entra-mcp-proxy-secrets
type: Opaque
stringData:
  DownstreamServers__0__OBO__ClientSecret: <real secret>
```

`appsettings.json` may contain non-secret defaults — Authority, TenantId, ClientId, the `Proxy` block, and the `DownstreamServers` shape — but MUST NOT contain `ClientSecret` values.

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

### Identity Delegation

For tools called by an authenticated user, the proxy exchanges the user's Entra access token for a downstream OBO token via RFC 8693 On-Behalf-Of (the `_targetScope` and `OBO.ClientSecret` configure the exchange). The downstream MCP server receives a token whose `oid` claim is the calling user's — audit logs at the downstream attribute the call to the real user.

For tool **discovery** (`tools/list` against each downstream at startup and on the configured refresh interval), the proxy optionally uses a service-principal token via the `client_credentials` grant if `DownstreamServers[*]:OBO:DiscoveryScope` is configured. Discovery defaults to **disabled** for the SP path — the operator must explicitly opt in by setting `DiscoveryScope` to a narrow scope like `{resource-id}/Discovery.Tools`. If `DiscoveryScope` is null, discovery only succeeds when a user request happens to trigger it.

This means:
- **Tool calls** are always under the calling user's identity (when the user authenticated). Audit logs are accurate.
- **Tool discovery** uses an optional service-principal token under a narrow configured scope. Operators who do not configure `DiscoveryScope` defer discovery to the first user request.
- **The proxy cannot grant access the user does not already have** — downstream ACLs are honored.

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
| `OBO.ClientSecret` | **Secret** — supply via env var or Key Vault, never in appsettings.json |
| `OBO.TargetScope` | Downstream resource scope, e.g. `{resource-id}/{scope}` |
| `OBO.DiscoveryScope` | Optional narrow scope for SP-mode tool discovery (null = disabled) |
| `ApiKey` | API key (when `AuthType` is `ApiKey`) |

### `Proxy`

| Key | Description | Default |
|---|---|---|
| `PublicBaseUrl` | External base URL of the proxy, used in OAuth discovery and WWW-Authenticate | required |
| `AllowedRedirectUris` | Exact allowlist of permitted `redirect_uri` values | required |
| `EgressAllowlist` | Hostname allowlist for outbound downstream connections | required |
| `RefreshIntervalMinutes` | How often the background service rediscovers tools from all downstream servers | `5` |
| `ToolResult:MaxBytes` | Maximum response body size from a tool call (bytes) | `262144` (256 KiB) |

---

## Entra ID Setup

### The easy way — one command

```bash
bash iac/setup-entra-app.sh     # or:  pwsh iac/setup-entra-app.ps1
```

This idempotent script does every step below — creates the app registration, exposes `user_impersonation`, adds the `Ado.Mcp.Tools` delegated permission, grants admin consent, mints a 2-year client secret, and (critically) sets `isFallbackPublicClient: true` so the smoke test's device-code grant can authenticate. It prints a ready-to-paste block for `iac/parameters.bicepparam`. **Use this unless you have a specific reason to provision by hand.**

The remaining sub-sections document the same configuration manually, in case your tenant policy requires portal-based registration or you need to audit what the script does.

### Step 1 — Register the Application

In **Microsoft Entra ID → App registrations**, create a new registration:

- **Supported account types:** Single tenant
- **Redirect URI:** Web platform — `https://claude.ai/api/mcp/auth_callback`

Note the **Application (client) ID** and **Directory (tenant) ID**.

### Step 2 — Enable "Allow public client flows"

In the new app's **Authentication** blade, scroll to *Advanced settings* and set **Allow public client flows** to **Yes** (Graph property `isFallbackPublicClient: true`). The app remains a confidential client for the proxy's authorization-code and OBO flows; this flag *additionally* permits the device-code grant the smoke script uses. Without it, the smoke script fails post-sign-in with `AADSTS7000218` even when a valid `client_secret` is sent — see [docs/changes/2026-05-22-stabilization.md §3](docs/changes/2026-05-22-stabilization.md) for the analysis.

### Step 3 — Create a Client Secret

Under **Certificates & secrets → New client secret**. Copy the value immediately.

This secret is used both by the proxy (to perform OBO exchanges) and by Claude Web (as `client_secret` in the token request). Store it in Azure Key Vault, a CI secret, or your password manager — never in source control.

### Step 4 — Expose an API Scope

Under **Expose an API**:

1. Set **Application ID URI** to `api://{client-id}`
2. Add a scope named `user_impersonation`
   - Who can consent: Admins and users

### Step 5 — Grant Permission for Azure DevOps Remote MCP

Under **API permissions → Add a permission → APIs my organization uses**, find:

- **Resource ID:** `2a72489c-aab2-4b65-b93a-a91edccf33b8`
- **Permission:** `Ado.Mcp.Tools` (delegated)

Click **Grant admin consent**. Required once. Without this, OBO exchange fails with `AADSTS65001`.

### Step 6 — Add Users to Azure DevOps

Users must exist in the Azure DevOps organization at `https://dev.azure.com/{org}/_settings/users`.

### Summary

| Configuration Key | Value |
|---|---|
| `EntraId:TenantId` | Directory (tenant) ID |
| `EntraId:ClientId` | Application (client) ID |
| `OBO:ClientSecret` | Client secret from Step 3 (via env var or Key Vault) |
| `OBO:TargetScope` | `2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools` |
| Claude Web `client_id` | Application (client) ID |
| Claude Web `client_secret` | Client secret from Step 3 |
| Claude Web MCP URL | `https://{your-proxy-domain}/mcp` |

---

## Deployment

The project ships a multi-stage `Dockerfile` targeting `mcr.microsoft.com/dotnet/aspnet:10.0`.

### Required Configuration

```yaml
# Kubernetes example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: entra-mcp-proxy
spec:
  template:
    spec:
      containers:
      - name: proxy
        image: entra-mcp-proxy@sha256:<digest>  # Pin by digest, not tag
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: Production
        - name: EntraId__Authority
          value: https://login.microsoftonline.com/{tenant-id}/v2.0
        - name: EntraId__TenantId
          value: {tenant-id}
        - name: EntraId__ClientId
          value: {client-id}
        - name: Proxy__PublicBaseUrl
          value: https://mcp.{your-domain}     # Used in OAuth discovery
        - name: Proxy__AllowedRedirectUris__0
          value: https://claude.ai/api/mcp/auth_callback
        - name: Proxy__EgressAllowlist__0
          value: mcp.dev.azure.com
        - name: DownstreamServers__0__Name
          value: "Azure DevOps"
        - name: DownstreamServers__0__Prefix
          value: azdevops
        - name: DownstreamServers__0__BaseUrl
          value: https://mcp.dev.azure.com/{your-org}
        - name: DownstreamServers__0__AuthType
          value: OBOToken
        - name: DownstreamServers__0__OBO__TenantId
          value: {tenant-id}
        - name: DownstreamServers__0__OBO__ClientId
          value: {client-id}
        - name: DownstreamServers__0__OBO__TargetScope
          value: 2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools
        envFrom:
        - secretRef:
            name: entra-mcp-proxy-secrets
```

### Forwarded Headers

This deployment does NOT trust `X-Forwarded-*` headers. The proxy's external URLs (discovery, OAuth metadata, WWW-Authenticate) derive from `Proxy:PublicBaseUrl` exclusively. Your ingress should still terminate TLS — Kestrel handles HTTP on the listening port — but the proxy's outbound URL signaling is independent of the ingress's header set.

### Health Check

```
GET /api/healthz → 200 { "status": "Healthy", "timestamp": "..." }
```

Exempt from authentication and rate limiting. Use as the liveness/readiness probe.

### Audit Logging

The category `EntraMcpProxy.Audit` emits one JSON record per security-relevant event. Pipe this category to an immutable store (Azure Monitor with immutability policy, SIEM, etc.). Other log categories are operational and can land in the normal application log stream.

### Docker

```bash
docker build -t entra-mcp-proxy .
docker run -p 8080:80 \
  -e EntraId__Authority="https://login.microsoftonline.com/{tenant}/v2.0" \
  -e EntraId__TenantId="{tenant}" \
  -e EntraId__ClientId="{client-id}" \
  -e Proxy__PublicBaseUrl="https://mcp.{your-domain}" \
  entra-mcp-proxy
```

---

## Security Posture

This deployment includes the following defenses:

| Defense | Where | Notes |
|---|---|---|
| JWT validation | `Program.cs` | Explicit issuer/audience/lifetime/signing key checks, 2-minute clock skew, `MapInboundClaims=false` |
| PKCE enforcement | `/authorize` | S256 required; rejected at proxy layer (not relying on Entra) |
| redirect_uri allowlist | `/authorize` | Exact ordinal match against configured list; https-only |
| Forwarded headers | (removed) | OAuth URLs derive from `Proxy:PublicBaseUrl`, never request headers |
| Rate limiting | `/authorize` + `/token` | Per-IP fixed window, configurable |
| Body size limit | `/token` | 8 KB |
| CORS | All endpoints | Configurable allowlist; empty list = no CORS |
| OBO cache key | `EntraIdOBOHandler` | `(oid, tid, aud, scope)` — collision-free |
| Cache TTL | `EntraIdOBOHandler` | Min(Entra `expires_in`, 10 min) |
| SP fallback | `EntraIdOBOHandler` | Gated behind `DiscoveryContext.Enter()` + explicit `DiscoveryScope` |
| Tool description provenance | `ToolPolicyService` | `[Source: downstream=...]` prefix on every description |
| Tool result provenance | `ToolResultWrapper` | `<downstream-content source=... tool=...>` wrapping |
| Tool result size cap | `ToolResultWrapper` | `Proxy:ToolResult:MaxBytes`, default 256 KiB |
| Per-tool authorization | `DownstreamAuthorizationFilter` | Optional; default = permit-all |
| Egress allowlist (config) | `DownstreamServerOptionsValidator` | Startup-time check |
| Egress allowlist (runtime) | `EgressEnforcingHandler` | Per-request check |
| Audit trail | `AuditLog` | JSON under `EntraMcpProxy.Audit` category |
| Exception handler | `GlobalExceptionHandler` | OBO + auth-namespace InvalidOps → 502 + sanitized; Production never echoes Entra body |

For the full threat model, see `docs/threat-model.md`. For deployment governance, see `docs/operations.md`.

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
- [Threat Model](docs/threat-model.md)
- [Operations Runbook](docs/operations.md)
