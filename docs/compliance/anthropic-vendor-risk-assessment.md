# Anthropic Vendor Risk Assessment — EntraMcpProxy

This is a template. Items marked `[OPERATOR-FILL]` must be completed by the
deploying organisation. The completed document should be reviewed and signed by
the risk owner before the proxy goes to production.

Vendor: Anthropic PBC
Service: claude.ai (MCP connector feature)
Assessment date: `[OPERATOR-FILL]`
Assessor: `[OPERATOR-FILL]`
Risk owner: `[OPERATOR-FILL]`

---

## 1 — What Credential Anthropic Holds

Anthropic's claude.ai infrastructure holds the Entra `client_secret` that the
operator registered for the proxy's Entra app registration.

Specifically:

- **Client ID**: the proxy's Entra app registration `appId` (not secret by itself)
- **Client secret**: a symmetric credential created in the Entra app registration
  and entered into claude.ai's MCP connector configuration by the operator

The secret is entered once during the claude.ai MCP connector setup and stored by
Anthropic to authenticate subsequent `/token` requests on behalf of claude.ai users.

**Justification for this design**: Microsoft Azure DevOps Remote MCP does not
support RFC 7591 Dynamic Client Registration. See
[microsoft/azure-devops-mcp#1077](https://github.com/microsoft/azure-devops-mcp/issues/1077).
The static `client_secret` is a necessary accommodation given the current state of
the Microsoft MCP implementation. This is documented as threat model finding M12
(`docs/threat-model.md`).

---

## 2 — What That Credential Can Do

If Anthropic's infrastructure is compromised and the `client_secret` is exfiltrated,
an attacker possessing both the `client_id` and `client_secret` could:

1. **Initiate the OAuth Authorization Code flow** against the proxy's `/authorize`
   endpoint on behalf of any user who visits a page the attacker controls — provided
   the attacker can supply a redirect URI. However, the redirect URI is pinned to
   `https://claude.ai/api/mcp/auth_callback` in the proxy config AND in the Entra
   app registration, so a leaked secret alone does not allow the attacker to
   redirect codes to an attacker-controlled endpoint.

2. **Exchange a legitimately issued authorization code for a token** at `/token`
   — but this requires the attacker to also intercept a valid authorization code,
   which requires intercepting a user's browser session.

3. **Impersonate the proxy to Entra** in an OBO exchange — if the attacker can
   obtain a user-signed JWT (the OBO `assertion`). This requires a valid user token
   issued by the operator's own Entra tenant, which the attacker does not have by
   default.

In summary: the `client_secret` alone enables impersonating the proxy to Entra but
does NOT grant direct access to user data without also compromising a user session
or an authorization code.

---

## 3 — What the Credential Cannot Do

With only the `client_id` + `client_secret`, an attacker:

- **Cannot** directly access Azure DevOps data, source code, work items, or any
  other downstream resource — because the proxy uses delegated OBO tokens, and an
  OBO exchange requires a valid user JWT as the `assertion`.

- **Cannot** bypass per-user OBO — each user's data is gated by their own Entra
  session. The proxy's OBO cache is keyed on `(oid, tid, scope)`; there is no
  cross-user token reuse.

- **Cannot** access tenant management or administer the Azure tenant — the app
  registration has only delegated `user_impersonation` and Azure DevOps
  `user_impersonation` scopes; no `Directory.Read.All` or similar.

- **Cannot** register additional redirect URIs — the proxy's Entra app registration
  enforces a static redirect URI allowlist, and changing it requires an Azure admin
  in the operator's tenant.

- **Cannot** issue tokens without PKCE — the proxy enforces `code_challenge` /
  `code_challenge_method=S256` on every authorization request.

---

## 4 — Mitigations in Place

| Mitigation | Description | Reference |
|---|---|---|
| Short secret rotation cadence | `client_secret` rotated every 90 days (or more frequently per org policy). Rotation procedure in `docs/operations.md`. | `docs/operations.md` §"Rotating the Entra client_secret" |
| Redirect URI allowlist | The proxy and the Entra app registration both enforce `https://claude.ai/api/mcp/auth_callback` as the only permitted redirect URI. | `docs/threat-model.md` §H3 |
| PKCE enforcement | Every authorization request requires `code_challenge` + `code_challenge_method=S256`. A leaked code is not redeemable without the verifier. | `docs/threat-model.md` §H4 |
| Per-user OBO model | The proxy never uses application-level tokens to access user data. Each OBO exchange is tied to the end user's JWT. | `Services/EntraIdOBOHandler.cs` |
| Audit logging of `/token` requests | Every token issuance is logged in the `EntraMcpProxy.Audit` category with `client_id`, `oid`, `tid`. Unusual patterns are detectable. | `docs/operations.md` §"Audit log review" |
| "Allow public client flows" disabled | Prevents the `client_secret` from being omitted in token requests. | Entra app registration — Step 1.5 of sandbox validation runbook |
| Rate limiting on `/token` | 30 requests per minute per IP by default. Reduces the effectiveness of credential-stuffing with a leaked secret. | `Services/` — rate limiter middleware |

---

## 5 — Residual Risk

After the mitigations above, the following risks remain:

| Risk | Severity | Notes |
|---|---|---|
| Anthropic infrastructure breach exposes `client_secret` | Medium | Mitigated by short rotation cadence and redirect URI allowlist. Impact limited: attacker needs a user's browser session to do anything useful. |
| Operator forgets to rotate `client_secret` on schedule | Low–Medium | Process risk. Mitigate by calendar reminder and secrets rotation tracker. |
| Anthropic insider threat — Anthropic employee accesses stored `client_secret` | Medium | Cannot be fully eliminated without ephemeral credentials (currently blocked by Microsoft). Mitigated by SOC 2 controls (see §6). |
| `client_secret` leaked via claude.ai browser extension / client-side code | Low | Unlikely — the secret is stored server-side in Anthropic infrastructure, not in the browser. |

---

## 6 — Questions to Ask Anthropic

Before final risk acceptance, obtain answers to the following questions from
Anthropic. Send these to Anthropic's security or enterprise team.

1. **SOC 2 Type II report**: Does Anthropic have a current SOC 2 Type II audit
   report? Can it be shared under NDA? Which trust service criteria does it cover
   (Security, Availability, Confidentiality)?

2. **Encryption at rest**: How is the `client_secret` stored in Anthropic's
   infrastructure? Is it encrypted at rest? What key management system is used?

3. **Access controls on Claude Web infrastructure**: Who within Anthropic can access
   stored MCP connector credentials? Is access logged and reviewed?

4. **Secret exfiltration detection**: Does Anthropic monitor for anomalous access
   to stored connector credentials?

5. **Breach notification SLA**: If Anthropic detects a breach that may have exposed
   stored MCP connector credentials, what is Anthropic's committed notification
   timeline to affected operators?

6. **Subprocessors**: Does Anthropic use any third-party subprocessors that handle
   MCP connector credentials? If so, what are their names and data processing
   agreements?

7. **Data residency**: In which geographic regions are MCP connector credentials
   stored?

8. **Penetration testing**: Does Anthropic conduct regular penetration testing of
   the claude.ai infrastructure? Can results summaries be shared?

Anthropic responses:

| Question | Response received | Date | Notes |
|---|---|---|---|
| SOC 2 Type II report | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Encryption at rest | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Access controls | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Breach notification SLA | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Subprocessors | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Data residency | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |
| Penetration testing | `[OPERATOR-FILL]` | `[OPERATOR-FILL]` | |

---

## 7 — Acceptance Criteria for Risk-Accept

`[OPERATOR-FILL: Complete the following criteria before signing the risk acceptance.]`

The vendor risk is accepted when ALL of the following conditions are met:

- [ ] Anthropic SOC 2 Type II report reviewed and no critical findings relevant to
  credential storage
- [ ] Breach notification SLA is ≤ 72 hours (or `[OPERATOR-FILL: org-specific requirement]`)
- [ ] `client_secret` rotation cadence is ≤ `[OPERATOR-FILL: e.g., 90 days]`
- [ ] Rotation procedure tested and confirmed working
- [ ] Risk owner accepts residual risk in writing (signature below)
- [ ] `[OPERATOR-FILL: Any additional org-specific acceptance criteria]`

---

## 8 — Risk Acceptance Sign-Off

| Field | Value |
|---|---|
| Risk accepted by | `[OPERATOR-FILL: Name and title]` |
| Date | `[OPERATOR-FILL]` |
| Residual risk rating | `[OPERATOR-FILL: e.g., Medium — acceptable with mitigations in place]` |
| Next review date | `[OPERATOR-FILL: e.g., 12 months after acceptance, or after any Anthropic security incident]` |
| Conditions attached | `[OPERATOR-FILL: Any conditions the risk owner places on the acceptance]` |
