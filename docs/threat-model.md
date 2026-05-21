# EntraMcpProxy — Threat Model

## Trust Boundaries

```
+-----------+   1   +----------+   2   +---------+   3   +---------------+
| Claude    +------>| Proxy    +------>| Entra   +------>| Azure DevOps  |
| Web       |       | (this)   |       | ID      |       | Remote MCP    |
+-----------+       +----------+       +---------+       +---------------+
                          |
                          | 4 (audit)
                          v
                    +---------+
                    | Immutable|
                    | sink     |
                    +---------+
```

1. **Claude Web → Proxy**: TLS-terminated by your ingress. The proxy trusts ONLY:
   - The Bearer token in the `Authorization` header (verified via Entra-signed JWT validation)
   - The OAuth `redirect_uri`, `code_challenge`, etc. parameters (each independently validated)
   - The configured `client_secret` (held by Anthropic per M12 below)

   The proxy does NOT trust `X-Forwarded-*` headers, the request `Host`, query parameters beyond the configured allowlist, or any client-supplied tool metadata.

2. **Proxy → Entra**: TLS to `login.microsoftonline.com`. The `client_secret` is the proxy's authentication credential. OBO exchange uses the user's JWT as the `assertion`; SP exchange uses `client_credentials` with an explicit `DiscoveryScope`.

3. **Proxy → Downstream MCP**: TLS to whatever the configured `BaseUrl` points at, gated by `Proxy:EgressAllowlist`. The `Authorization` header carries either the OBO-exchanged user token OR (for discovery-context calls) the SP token.

4. **Proxy → Audit Sink**: Out-of-band log shipping. The `EntraMcpProxy.Audit` logger category should be piped to an immutable store (Azure Monitor with immutability, SIEM).

## Trust Assumptions

### M12 — Anthropic / Claude Web holds the Entra `client_secret`

The proxy's OAuth Authorization-Server facade requires Claude Web to authenticate to the proxy's `/token` endpoint with the same Entra `client_id` + `client_secret` registered in the corporate tenant. Microsoft's Azure DevOps Remote MCP cannot use RFC 7591 Dynamic Client Registration (see [microsoft/azure-devops-mcp#1077](https://github.com/microsoft/azure-devops-mcp/issues/1077)), so the secret cannot be ephemerally minted per session.

**Implication**: Anthropic operates infrastructure that holds a credential capable of impersonating the proxy's Entra app registration. Mitigations:

- Rotate the `client_secret` on a short cadence (~90 days).
- Scope the Entra app registration to the minimum required permissions (currently `Ado.Mcp.Tools` delegated, `user_impersonation`).
- Pin redirect URI to `https://claude.ai/api/mcp/auth_callback` only.
- Disable "Allow public client flows" in the Entra app registration.
- Monitor the `EntraMcpProxy.Audit` log for unusual `/token` patterns.

### Network Trust

The proxy assumes its Kestrel listener is reachable only via the ingress (which terminates TLS and forwards HTTP). It does NOT validate `X-Forwarded-For`, IP allowlisting, or similar — those should be enforced at the ingress.

### Configuration Trust

The proxy assumes:
- `appsettings.json` is part of the immutable container image.
- Secrets are injected via environment variables from a secret store (Azure Key Vault provider, Kubernetes Secret, etc.).
- Changes to `DownstreamServers[*]` require a deployment, not a hot-reload (the proxy reads config once at startup).

## Residual Risks

### R1 — Compromised Downstream MCP

If a configured downstream (e.g., the Azure DevOps Remote MCP) is compromised and serves malicious tool metadata or content:

- **Tool descriptions and schemas** are partially mitigated by Phase 9 defenses: `[Source: downstream=...]` provenance prefix, schema validation (external `$ref` and vendor extensions rejected), tool name allowlist per downstream.
- **Tool call results** are partially mitigated by Phase 10: `<downstream-content source=...>` wrapping signals to Claude that the content is downstream-provided, not authoritative.
- **The model is the last line of defense**. The wrappers are prompt-injection-resistant by convention, not by mechanism. A sufficiently clever payload may still influence Claude.

Compensating controls:
- Pin downstream to known-good MCP servers in `Proxy:EgressAllowlist`.
- Audit `tool_set_changed` events for unexpected additions or description changes (Phase 12 emits these as audit records).

### R2 — Per-tool Authorization is Opt-In

The default policy is permit-all to preserve backward compatibility with claude.ai's MCP connector. Restrictive policies (`Proxy:Authorization:Tools`) are an operator choice. For deployments where not all users should access all tools, operators must configure the policy explicitly.

### R3 — DiscoveryScope null disables SP-mode tool discovery

The N3 fix removed the implicit `.default` SP scope. Operators who don't configure `Proxy:DownstreamServers:0:OBO:DiscoveryScope` will see tool discovery only happen after a user request comes in to drive it. This is the secure default; operators wanting startup discovery should configure a narrow scope.

### R4 — Audit Sink Reliability

The audit logger writes to `EntraMcpProxy.Audit`. If this category is not piped to an immutable store, audit events live only in ephemeral container logs and are lost on restart. Operators must configure log shipping before treating the audit trail as investigation-grade.

## Defense-in-depth Layers per Finding

| Finding | Layer 1 (primary) | Layer 2 (DiD) |
|---|---|---|
| C1 | OboCacheKey value equality | SHA-256 hash bucket |
| C2 | OboCacheKey + per-request OBO | Two-user concurrency test |
| H3 | RedirectUriValidator allowlist | Entra app registration allowlist |
| H4 | PkceValidator at proxy | Entra PKCE enforcement |
| H5 | PublicBaseUrl config-only | UseForwardedHeaders removed |
| H6 | DiscoveryContext gate | DiscoveryScope required |
| H7 | OboExchangeException sanitized message | GlobalExceptionHandler 502 + generic detail |
| N5 | Tool description provenance | InputSchema validator |
| N11 | Tool result wrapping | Size budget |
| N16 | EntraMcpProxy.Audit JSON | Operational sink immutability |
| N19 | Config validator | EgressEnforcingHandler runtime |
