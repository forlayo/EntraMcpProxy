# EntraMcpProxy — SOX Control Mapping

This document maps SOX-relevant IT General Controls (ITGCs) to the features and
configurations of EntraMcpProxy. It is a **template** — items marked
`[OPERATOR-FILL]` must be completed by the deploying organisation before an audit.

Last updated: 2026-05-22
Control owner: `[OPERATOR-FILL: Name and title]`
System name: EntraMcpProxy
System classification: `[OPERATOR-FILL: e.g., "Tier 2 — supports financial reporting system"]`

---

## 1 — Access Controls

### 1.1 Authentication

| Control | How EntraMcpProxy implements it |
|---|---|
| Users authenticate before accessing financial data | All `/mcp` routes require a valid Entra-signed JWT (`Authorization: Bearer`). Unauthenticated requests receive HTTP 401. |
| Authentication is delegated to a trusted IdP | Entra ID v2.0 is the sole authentication authority. The proxy validates JWTs against Entra's published JWKS (`{tenant}/discovery/v2.0/keys`). |
| Multi-factor authentication | `[OPERATOR-FILL: Confirm whether a Conditional Access policy requiring MFA is applied to the proxy's Entra app registration.]` |
| Credential type | OAuth 2.0 Authorization Code + PKCE. No password-based auth. |
| PKCE enforcement | The proxy rejects any `/authorize` request that omits `code_challenge` and `code_challenge_method=S256` (finding H4, `Services/PkceValidator.cs`). |

Operator additional controls:
- `[OPERATOR-FILL: IP-based allowlisting at ingress layer (if applicable)]`
- `[OPERATOR-FILL: Conditional Access policy reference and enforcement date]`

### 1.2 Authorisation

| Control | How EntraMcpProxy implements it |
|---|---|
| Users access only tools they are authorised for | Per-tool authorisation policy (`Proxy:Authorization:Tools`) restricts tool calls by Entra group membership. Default is permit-all; production deployments MUST configure explicit policies. |
| Principle of least privilege | Azure DevOps `user_impersonation` is a delegated permission — the proxy acts on behalf of the user, never with elevated application permissions. |
| No service-account bypass | All tool calls use On-Behalf-Of (OBO) tokens tied to the end user's `oid`. OBO cache is keyed on `(oid, tid, scope)` — cross-user token reuse is structurally prevented. |

Operator additional controls:
- `[OPERATOR-FILL: List Entra group IDs mapped to tool patterns in Proxy:Authorization:Tools]`
- `[OPERATOR-FILL: Confirm permit-all is NOT the production policy, or document the business justification if it is]`

### 1.3 Redirect URI Allowlist

The proxy enforces a static allowlist of permitted OAuth redirect URIs
(`Proxy:AllowedRedirectUris`). Any `/authorize` request with a `redirect_uri`
not in the list is rejected with HTTP 400 (`redirect_uri_rejected`). This prevents
open-redirect attacks that could exfiltrate authorization codes.

Production allowlist value: `https://claude.ai/api/mcp/auth_callback`

Operator: `[OPERATOR-FILL: Confirm no additional redirect URIs are present in production]`

---

## 2 — Change Management

### 2.1 Git-Based Change History

All changes to the proxy's source code, configuration templates, and
infrastructure-as-code are tracked in Git. Every change has an author, timestamp,
and commit message.

Repository: `[OPERATOR-FILL: e.g., github.com/your-org/EntraMcpProxy]`
Branch protection: `[OPERATOR-FILL: Confirm main branch requires PR + review]`

### 2.2 CI Gates

The GitHub Actions workflow (`.github/workflows/`) enforces:

- Build compilation (zero errors)
- Unit tests (must pass)
- Integration tests (must pass)
- E2E tests (must pass)
- Vulnerability scan (`dotnet list package --vulnerable` — blocks on High/Critical)
- SBOM generation

No merge to `main` is permitted if CI is failing.

`[OPERATOR-FILL: Link to CI system dashboard or workflow run history]`

### 2.3 PR Review

Branch protection requires at least one approved review before merge.

`[OPERATOR-FILL: Number of required reviewers]`
`[OPERATOR-FILL: Who is authorised to approve PRs (team or individuals)]`
`[OPERATOR-FILL: CODEOWNERS file or equivalent access control]`

### 2.4 Deployment Authorization

`[OPERATOR-FILL: Describe the change advisory board (CAB) or change ticket process for production deployments]`
`[OPERATOR-FILL: Who approves production deployments?]`
`[OPERATOR-FILL: Emergency change procedure]`

### 2.5 Configuration Change Control

Changes to `DownstreamServers` in production require:

1. Security review of the new downstream MCP's tool catalog
2. Update to `Proxy:EgressAllowlist` in the same PR
3. CI gates passing
4. PR review approval
5. Deployment via the standard pipeline (not hotfix/manual)

`[OPERATOR-FILL: Confirm this procedure is documented in your change management system]`

---

## 3 — Audit Logging

### 3.1 What is Logged

EntraMcpProxy emits structured JSON audit events via the `EntraMcpProxy.Audit`
logger category. Events include:

| Event type | Fields |
|---|---|
| `oauth_authorize_started` | `client_id`, `redirect_uri`, `state`, `pkce_present` |
| `oauth_token_issued` | `client_id`, `oid`, `tid`, scope |
| `tool_invocation` | `tool_name`, `oid`, `tid`, `downstream`, `status`, `duration_ms` |
| `authz_denied` | `tool_name`, `oid`, `tid`, `reason` |
| `obo_exchange_failed` | `oid`, `tid`, `error` |
| `redirect_uri_rejected` | `redirect_uri_attempted`, `client_id` |
| `pkce_missing` | `client_id`, `state` |
| `tool_set_changed` | `downstream`, `added_tools`, `removed_tools` |
| `egress_blocked` | `requested_host`, `allowed_hosts` |

### 3.2 Immutable Sink

Audit events are written to an immutable store to satisfy audit log integrity
requirements.

Sink type: `[OPERATOR-FILL: e.g., Azure Monitor with immutability policy, Splunk with WORM indexer, S3 with Object Lock]`
Retention period: `[OPERATOR-FILL: e.g., 7 years for SOX]`
Wiring reference: `docs/audit-sink-wiring.md`
Immutability confirmed: `[OPERATOR-FILL: Date tested and by whom]`

### 3.3 Log Review

Weekly audit log review procedure: see `docs/operations.md` §"Audit log review (weekly)".

Reviewer: `[OPERATOR-FILL: Role or team responsible for weekly review]`
Escalation path: `[OPERATOR-FILL: Who reviews anomalies found during weekly review]`
Review evidence archived: `[OPERATOR-FILL: Where review tickets or notes are stored]`

---

## 4 — Segregation of Duties

The following roles must be held by distinct individuals or teams. Where the
organisation is too small to separate all roles, compensating controls are
documented below.

| Duty | Role description | Assigned to |
|---|---|---|
| Deploy to production | Execute container image deployments; update env vars | `[OPERATOR-FILL]` |
| Review audit logs | Read audit log sink; investigate anomalies | `[OPERATOR-FILL]` |
| Own Entra app registration | Create/delete/rotate `client_secret`; manage redirect URIs | `[OPERATOR-FILL]` |
| Approve code changes | PR reviewer; cannot approve own changes | `[OPERATOR-FILL]` |
| Manage secrets store | Read/write to Key Vault or equivalent | `[OPERATOR-FILL]` |

Compensating controls where duties overlap:
`[OPERATOR-FILL: e.g., "Deploy engineer and audit log reviewer are the same person; compensating control is a second-person sign-off requirement for any deployment during an audit period."]`

---

## 5 — Data Classification

### 5.1 Data in Transit

The following data transits EntraMcpProxy during normal operation:

| Data element | Classification | Notes |
|---|---|---|
| Entra JWT (user token) | Confidential — Identity | Contains `oid`, `tid`, `scp`; used to authenticate the user; forwarded only to Entra for OBO exchange |
| OAuth authorization code | Confidential — Credential | Short-lived, one-time-use; transmitted over TLS only |
| OBO access token | Confidential — Credential | Used to authenticate to Azure DevOps on behalf of the user; not logged |
| `client_secret` | Confidential — Credential | Never logged; stored in secret store only |
| Tool call arguments | `[OPERATOR-FILL: e.g., Internal — may include project names, work item IDs]` | Logged as part of `tool_invocation` audit event; review what fields are included |
| Tool call results | `[OPERATOR-FILL: e.g., Internal — may include source code, work item content]` | NOT logged in audit events; result body is proxied to claude.ai |
| User identity (`oid`, `tid`) | Confidential — PII | Logged in all audit events; included in audit retention period review |

### 5.2 Data at Rest

- OBO tokens: held in an in-memory cache only; lost on restart. Not persisted to disk.
- Audit logs: written to the configured sink. Classification follows the sink's data classification.
- `client_secret`: stored in the secrets management system. See section 2 of the secrets management policy.

### 5.3 Data Processing Agreement

`[OPERATOR-FILL: Confirm a DPA is in place with Anthropic (claude.ai processes auth flows and tool results). Reference the DPA document and date signed.]`

---

## 6 — Vendor Management (Anthropic)

See `docs/compliance/anthropic-vendor-risk-assessment.md` for the full vendor risk
assessment.

Summary of Anthropic's role:

- Anthropic operates claude.ai, which initiates the OAuth Authorization Code flow
  against the proxy.
- Anthropic holds the Entra `client_secret` (registered by the operator in their
  tenant) to authenticate to the proxy's `/token` endpoint.
- Anthropic's infrastructure processes tool call results returned by the proxy.

Control: `[OPERATOR-FILL: Confirm that the Anthropic vendor risk assessment has been reviewed and risk-accepted by the appropriate stakeholder. Include date and name.]`

Periodic review: `[OPERATOR-FILL: Frequency of vendor risk re-assessment, e.g., annually]`

---

## Document Control

| Field | Value |
|---|---|
| Document owner | `[OPERATOR-FILL]` |
| Approved by | `[OPERATOR-FILL]` |
| Approval date | `[OPERATOR-FILL]` |
| Next review date | `[OPERATOR-FILL]` |
| Related documents | `docs/threat-model.md`, `docs/operations.md`, `docs/audit-sink-wiring.md`, `docs/compliance/anthropic-vendor-risk-assessment.md` |
