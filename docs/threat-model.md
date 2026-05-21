# EntraMcpProxy — Threat Model

> **Status: STUB.** This document is created during Phase 5 to capture the
> M12 trust-assumption note that operators must understand before deploying.
> Full threat-model content (trust boundaries diagram, residual-risk catalog,
> defense-in-depth mapping) is filled in during Phase 16 (Documentation) of
> the remediation plan: `docs/superpowers/plans/2026-05-21-entra-mcp-proxy-remediation.md`.

---

## Trust Assumptions

### Anthropic / Claude Web holds the Entra `client_secret` (finding M12)

The proxy's OAuth Authorization-Server facade requires Claude Web to
authenticate to the proxy's `/token` endpoint with the same Entra
`client_id` + `client_secret` registered in the corporate tenant. Microsoft's
Azure DevOps Remote MCP cannot use RFC 7591 Dynamic Client Registration
(see [microsoft/azure-devops-mcp#1077](https://github.com/microsoft/azure-devops-mcp/issues/1077)),
so the secret cannot be ephemerally minted per session.

Implication: **Anthropic operates infrastructure that holds a credential
capable of impersonating the proxy's Entra app registration.** If that
credential leaks, the leak vector is one of:

- Anthropic Claude Web compromise of the credential store.
- An insider with access to Anthropic's Claude Web infrastructure.
- A compromise of the operator's Claude Web account that exfiltrates the
  configured `client_secret`.

Mitigations available to the deploying organisation:

- Rotate the Entra `client_secret` on a short cadence (~90 days).
- Scope the Entra app registration to the minimum required permissions
  (currently `Ado.Mcp.Tools` delegated on resource
  `2a72489c-aab2-4b65-b93a-a91edccf33b8`, plus `user_impersonation`).
- Pin redirect URI to the Claude Web callback only (enforced in code by
  `Proxy:AllowedRedirectUris`, finding H3).
- Disable the Entra app registration's "Allow public client flows" toggle.
- Audit-log every `/token` exchange (Phase 12).

This assumption is **not removable by code changes in this repository**;
it is structural to how the integration works today.

---

## Other Sections (Phase 16)

To be filled in during Phase 16:

- Trust-boundary diagram (Claude Web → proxy → Entra → Azure DevOps MCP)
- Residual-risk catalog (per-tool authorization opt-in, downstream-MCP
  trust, …)
- Defense-in-depth mapping per audit finding
