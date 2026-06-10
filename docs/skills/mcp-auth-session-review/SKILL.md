---
name: mcp-auth-session-review
description: Use when Codex needs to review or fix MCP servers, Claude.ai connectors, remote MCP OAuth flows, or proxy deployments where users must log in repeatedly, reconnect after a while, lose MCP sessions after container restarts, or fail after OAuth appears to succeed.
---

# MCP Auth Session Review

## Core Rule

Do not guess that "OAuth is flaky." Classify the repeated login into one failing layer: MCP endpoint discovery, OAuth protected-resource metadata, token issuance, refresh-token use, downstream OBO exchange, server-side MCP session state, or container persistence.

## Evidence to Collect

Start from the exact URL configured in the client, including path. For Claude.ai this is often `https://host/mcp`, not just `https://host`.

Collect logs for two moments:

1. A fresh login that works.
2. A later use that asks the user to log in again, ideally after access-token expiry or the next day.

Log only safe token diagnostics:

- `grant_type`
- requested scopes, without secrets
- `expires_in`
- `refresh_token_present`
- token endpoint status and Entra error code
- exact MCP route hit
- whether `MCP-Session-Id` was sent or returned
- downstream/OBO token status, without token values

## Probe the MCP Auth Surface

Run unauthenticated probes against the exact configured MCP URL:

```bash
curl -i -X POST "$MCP_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

Expected result: `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.

Fetch the protected resource metadata URL. Expected result:

- `resource` exactly equals the configured MCP URL.
- `authorization_servers` points to the auth-server root.
- scopes match what the connector needs.

Then probe the same exact MCP URL with a valid access token. Expected result: MCP `initialize` succeeds, not `404`, not a bare `401`, and not a different route.

## Failure Map

| Observation | Likely cause | Fix direction |
| --- | --- | --- |
| Fresh OAuth token exchange returns `200`, then client still fails | MCP path or metadata mismatch | Map the exact configured path and make metadata `resource` match it |
| Unauthenticated MCP request returns bare `WWW-Authenticate: Bearer` | Client cannot discover OAuth metadata | Add RFC 9728 protected-resource metadata challenge before the default bearer challenge |
| `/mcp` challenge works but authenticated `/mcp` returns `404` | Metadata fallback exists but route is not mapped | Map `/mcp` as a real MCP endpoint and protect it |
| `refresh_token_present=false` on the initial token response | No reusable credential was issued | Request/consent `offline_access`; verify app registration and client type |
| Later use starts a new authorization flow instead of `grant_type=refresh_token` | Client did not store or reuse refresh token | Prove from logs; server cannot silently refresh if the client never sends a refresh grant |
| Refresh grant returns `invalid_grant` | Refresh token rejected | Check Conditional Access sign-in frequency, revoked sessions, password reset, consent changes, tenant policy, or client secret rotation |
| MCP works until restart, scale-out, or next revision | In-memory MCP session or cookie/session protection | Enable stateless MCP transport, durable session storage, sticky sessions, or persisted ASP.NET DataProtection keys depending on what is being stored |
| Downstream/OBO fails after connector auth succeeds | User token is valid for connector but downstream exchange fails | Inspect OBO audience, scopes, consent, and downstream token cache separately |

## Fix Checklist

Use stateless MCP transport for tool-only gateways unless the server genuinely requires durable per-client MCP sessions. If state is required, store it durably; do not depend on per-container memory in scaled container apps.

Ensure every public MCP URL a client can configure is a real protected MCP route. Avoid advertising `/mcp` in metadata or docs while only mapping `/`.

Ensure the first unauthenticated MCP request can discover protected resource metadata. The default framework bearer challenge is often not enough for remote MCP clients.

Ensure OAuth authorization requests include the scopes needed for refresh behavior, especially `offline_access` when the platform supports refresh tokens.

Persist DataProtection keys if cookies, OIDC correlation state, or server-side protected tickets survive container restarts. Do not treat this as a replacement for client refresh tokens.

Add regression tests for:

- exact configured MCP path works with a valid token
- unauthenticated MCP requests include `resource_metadata`
- protected resource metadata `resource` matches the exact MCP URL
- stateless transport does not issue or require `MCP-Session-Id`, or session state survives restart if stateful
- token endpoint diagnostics prove whether refresh tokens are issued and refresh grants are accepted

## Expected Fixed Behavior

After the user logs in once, the connector should use the access token until it expires. On later use, including tomorrow, it should refresh silently using a refresh token or equivalent client-managed credential. The user should see a login prompt only when the refresh credential is revoked, tenant policy requires a fresh sign-in, consent/scopes changed, or the client did not persist the refresh credential.

## Standalone Prompt

Use this prompt in another MCP server repo:

```text
Act as a senior engineer debugging a remote MCP OAuth connector where users must log in repeatedly. Do not propose fixes before classifying the failure layer.

First collect the exact MCP URL configured in the client, including path, plus logs for one fresh successful login and one later use that asks for login again. Inspect the MCP unauthenticated challenge, protected resource metadata, authenticated MCP route, token endpoint grant types, refresh_token presence, refresh grant result, downstream/OBO exchange, MCP-Session-Id behavior, and container restart/scale events.

Create a findings table with: observed evidence, failing layer, root cause, code/config fix, regression test. Prioritize fixes that make the exact configured MCP path real, emit RFC 9728 resource_metadata on 401, request/consent offline_access when refresh tokens are expected, use stateless MCP transport or durable session storage, and persist DataProtection keys when cookies or protected tickets are used.

Finish by stating the expected next-day behavior after the fix: whether the client should refresh silently, and the specific policy or revocation events that can still force re-login.
```
