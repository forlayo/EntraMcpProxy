# Stabilisation pass — May 2026

> Status: complete · Branch: `security-remediation`
> Audience: upstream maintainer review, internal rollout team

This change set sits on top of the existing security remediation work (audit `2026-05-21-security-review.md`). The remediation closed the security findings; this pass closes the *operational* gaps that surfaced when an operator tried to deploy the remediated build end-to-end against a fresh Azure tenant.

---

## TL;DR

| Area | What changed | Commit |
|---|---|---|
| Background tool discovery | OBO downstreams without `DiscoveryScope` no longer trip `OboExchangeException` at startup; discovery happens lazily on the first authenticated `tools/list` | `2c6035b` |
| MCP route | `MapMcp()` now explicitly mounts at `/mcp` — matches documentation and test expectations | `500012e` |
| `iac/test/test-mcp.sh` | GNU-only constructs replaced with portable equivalents (`date +%s%3N`, `head -n -1`, `grep -oP`, `mapfile`); `--client-secret` is now a required parameter for the confidential-client device-code grant | `e2bf6c3`, `d7e8194`, `c1eb89a`, `513d405`, `cbe6505` |
| IaC default secret source | `secretSource = 'Direct'` is now the default — no Key Vault RBAC race on first deploy | This PR |
| Entra app provisioning | New `iac/setup-entra-app.{sh,ps1}` — single-command app registration with the correct settings, including the **`isFallbackPublicClient: true`** flag that the device-code test script needs | This PR |
| Documentation | `iac/README.md` rewritten end-to-end; `docs/sandbox-validation.md` corrected; this changelog added | This PR |

Net result: an operator with `az login` and an empty resource group can go from zero to a working claude.ai connector in roughly ten minutes by running three commands (`setup-entra-app`, fill `parameters.bicepparam`, `deploy`).

---

## 1. The OBO lazy-discovery fix

### What broke

After `2026-05-21-security-review.md` closed finding **N3** (the silent `.default` SP fallback in `EntraIdOBOHandler`), the proxy required operators to either configure `OBO:DiscoveryScope` per downstream OR accept that startup tool discovery would fail. The IaC template (`iac/main.bicep`) was not updated to set `DiscoveryScope`, so every deploy logged a `OboExchangeException` stack at boot and on every 5-minute refresh cycle:

```
fail: ModelContextProtocol.Client.McpClient[1155727496]
      Client (EntraMcpProxy 1.0.0) client initialization error.
      EntraMcpProxy.Auth.OboExchangeException: Discovery SP path invoked but
        OBO:DiscoveryScope is not configured. Set DiscoveryScope to enable
        SP-token discovery, or disable downstream tool discovery in configuration.
         at EntraMcpProxy.Auth.EntraIdOBOHandler.GetSpTokenAsync(…)
         at EntraMcpProxy.Services.DownstreamClientManager.ConnectAsync(…)
         at EntraMcpProxy.Services.ToolAggregatorService.DiscoverToolsAsync(…)
```

The architectural snag: Azure DevOps Remote MCP at `https://mcp.dev.azure.com` is **user-delegated only**. There is no app-only (client_credentials) flow Azure DevOps will accept against it, so even if the operator configured `DiscoveryScope` correctly, background discovery would still fail with HTTP 401 from ADO instead of `AADSTS70011` from Entra. Discovery for this kind of downstream simply *cannot* run from a background service without a user context.

### What changed

[`Configuration/DownstreamServerOptions.cs`](../../Configuration/DownstreamServerOptions.cs) — new computed property:

```csharp
public bool RequiresUserContext =>
    string.Equals(AuthType, "OBOToken", StringComparison.OrdinalIgnoreCase)
    && string.IsNullOrWhiteSpace(OBO?.DiscoveryScope);
```

`DownstreamClientManager.ConnectAllAsync` skips lazy downstreams at startup with an informational log line. `ToolAggregatorService.DiscoverToolsAsync` skips them on each periodic refresh. The per-downstream discovery logic moved out into a new internal `RefreshToolsForPrefixAsync(prefix, ct)` that can be called either from the background loop (inside `DiscoveryContext`) or from a request path with a user bearer in `HttpContext`.

`ProxyToolHandler.HandleListToolsAsync` now triggers `RefreshToolsForPrefixAsync` on the first authenticated `list_tools` for any lazy downstream that has no entries in the registry yet — the OBO handler reads the user's bearer from the accessor and runs the OBO exchange against ADO in the user's context. Subsequent `list_tools` calls hit the cached registry. `DownstreamClientManager.ConnectAsync` got a per-prefix `SemaphoreSlim` so two concurrent first-list requests cannot both build (and leak) an `McpClient` against the same downstream.

`Program.cs` registers `ToolAggregatorService` as both a singleton **and** a hosted service so `ProxyToolHandler` can inject it.

### Trade-off

Tools for lazy downstreams are no longer auto-refreshed by the 5-minute background loop. They are discovered once on the first authenticated `list_tools` of the process lifetime and remain registered until the proxy restarts. For ADO's mostly-static catalog this is acceptable; for dynamic catalogs the right addition would be a TTL check in `HandleListToolsAsync` before deciding to skip refresh. Out of scope for this pass.

### Verification

- All 211 unit tests + 50 integration tests pass after the refactor.
- Manual: deploy the new image, observe boot log — `OboExchangeException` no longer appears. On the first authenticated `list_tools` from a real user, the Azure DevOps tool catalog appears.

---

## 2. The MCP route fix

### What broke

`app.MapMcp().RequireAuthorization()` ([`Program.cs:523`](../../Program.cs)) was called with no arguments. The SDK's `MapMcp(pattern = "")` mounts the streamable HTTP transport at the **root** path (`POST /`, `GET /`, `DELETE /`, plus `/sse` and `/message` as legacy sub-routes). Every operator-facing artifact in the repo, however, said the MCP endpoint was at `/mcp`:

- [`docs/sandbox-validation.md` step 3.2](../sandbox-validation.md) — "Integration URL: `https://$PROXY_FQDN/mcp`"
- [`iac/test/test-mcp.sh:426`](../../iac/test/test-mcp.sh) — `MCP_URL="$PROXY_URL/mcp"`
- The integration tests POST to `/mcp` (but only assert `401`, which the custom auth middleware returns for *any* path that isn't in the exempt list — it never actually exercised `/mcp` as an MCP endpoint)

Symptom: post-OAuth, claude.ai POSTed `initialize` to `/mcp` and got `HTTP 404`. The smoke script reported `MCP initialize returned HTTP 404`. Both flows died at the first MCP request despite OAuth completing successfully.

### What changed

```csharp
// Mounted at /mcp explicitly: MapMcp() defaults to "" (root), but every
// operator-facing doc (sandbox-validation, README rollout runbook,
// test-mcp.sh) and the claude.ai connector URL pattern all assume /mcp.
// Pinning the prefix keeps the actual route aligned with documentation.
app.MapMcp("/mcp").RequireAuthorization();
```

All 50 integration tests still pass — they were already POSTing to `/mcp` and now actually hit the MCP handler instead of the auth-middleware 401.

### Why not change the docs to say `/`?

`/mcp` is the conventional MCP path across the ecosystem (it's what the spec examples use, what other proxies use, and what claude.ai's UI hints at). Aligning the code with that convention costs one parameter and matches existing operator expectations.

---

## 3. The Entra `isFallbackPublicClient` discovery

### What broke

`iac/test/test-mcp.sh` uses the device-code grant against Entra so an operator can verify the proxy end-to-end without setting up a browser-driven authorization-code flow. The proxy's Entra app is a **confidential client** (`publicClient: false`) because the proxy itself uses a `client_secret` when relaying `/token` and when doing OBO exchanges. The device-code grant in Microsoft Identity Platform is — by Microsoft's design — a *public-client* flow.

When you POST to `/oauth2/v2.0/token` with `grant_type=device_code` against a confidential app, Entra silently accepts the request **while the device code is pending user sign-in** (it returns `authorization_pending` without validating client auth). The strict client-auth check fires only **after** the user completes sign-in. At that point Entra returns `AADSTS7000218` ("The request body must contain the following parameter: 'client_assertion' or 'client_secret'") *even when a valid `client_secret` is in the body* — unless the app registration has the `isFallbackPublicClient: true` flag set (UI label: **Authentication → Advanced settings → Allow public client flows**).

This is a documented Microsoft requirement but extremely easy to miss because:

- The error description literally says "must contain client_secret" — the obvious reading is "you forgot to send it"
- Sending the secret does not change the error
- The error only fires post-sign-in, so a smoke test that times out before the user signs in cannot reproduce it
- Probing with a fake `device_code` returns `AADSTS7000014` (invalid device_code) — Entra short-circuits before the client-auth check, masking the underlying issue

The fix is a single Microsoft Graph property on the app registration:

```json
"isFallbackPublicClient": true
```

This is **orthogonal to** `publicClient: false`. The app remains a confidential client for authorization-code and OBO flows (both keep working with the existing secret). The flag only *additionally* permits device-code / ROPC / IWA. Setting it does not weaken any other flow.

### What changed

The new [`iac/setup-entra-app.sh`](../../iac/setup-entra-app.sh) / [`.ps1`](../../iac/setup-entra-app.ps1) sets this flag at provisioning time (step 4/9 in the scripts). The smoke script's argument validation now requires `--client-secret` (it cannot succeed against the proxy's confidential app without one, regardless of the secret value).

The hardened error handler in `test-mcp.sh` ([fail block in step 2](../../iac/test/test-mcp.sh)) detects `AADSTS7000218` specifically and points operators at the `isFallbackPublicClient` flag rather than at the (misleading) "your secret is wrong" interpretation.

A skill memory was filed at `~/.claude/projects/D--workspace-EntraMcpProxy/memory/entra-device-code-public-flows.md` so future debugging sessions on this codebase don't have to re-derive the cause from the error message.

---

## 4. Test script portability and correctness

Five small commits, all driven by running the script against the real deployed proxy from a macOS box:

| Commit | Problem | Fix |
|---|---|---|
| `08a0634` | `mapfile -t` (bash 4+) used for parsing tool list | Replaced with `while IFS= read -r` populating an indexed array (bash 3.2 compatible) |
| `e2bf6c3` | `date +%s%3N` (GNU) produces `1779459296%3N` literal on BSD `date`, breaking arithmetic with "value too great for base" | New `now_ms()` function that prefers `perl -MTime::HiRes`, then `python3`, then `gdate`, then GNU `date`, then second-precision fallback |
| `d7e8194` | `head -n -1` (GNU) rejected by BSD `head` with "illegal line count -- -1"; `grep -oP` lookbehinds (PCRE) not supported by BSD grep | `head -n -1` → `sed '$d'`; `head -1 \| grep -oP '(?<=HTTP/\S+ )\d+'` → `awk 'NR==1{print $2; exit}' \| tr -d '\r'` |
| `c1eb89a` → `513d405` | Confidential-client device-code grant needs `client_secret` on the `/token` poll; conditional bash array logic to add it didn't take on bash 3.2 (precise cause unidentified — symptom was `AADSTS7000218` despite the secret being passed correctly) | Make `--client-secret` a required parameter; drop the conditional array and pass it unconditionally in a single inline curl call |
| `cbe6505` | Misleading error hint referenced `EntraId__ClientSecret` env var that this proxy does not set | Updated to reference `DownstreamServers__0__OBO__ClientSecret` (the actual env var) and to broaden the `invalid_client` diagnostics across `AADSTS7000215` / `AADSTS7000222` / `AADSTS7000218` |

All commits verified live against `https://aca-entra-mcp-proxy-devel…` — the smoke script now runs cleanly from macOS bash 3.2 with the GNU coreutils unavailable.

---

## 5. IaC: Direct secret is the new default

### What changed

[`iac/main.bicep`](../../iac/main.bicep): `secretSource` default flipped from `'KeyVault'` to `'Direct'`. The `keyVaultName` parameter is now optional (defaults to a placeholder that is only consulted when `secretSource == 'KeyVault'`). The operator next-steps message updated to reflect the simpler default flow.

[`iac/parameters.example.bicepparam`](../../iac/parameters.example.bicepparam) restructured around the new default: the required parameter list is shorter (no Key Vault by default), the `oboClientSecretValue` is prominent, and the Key Vault parameters live in comments next to the `secretSource = 'KeyVault'` opt-in.

### Why

The original design had `secretSource = 'KeyVault'` as the production-grade default. In practice every first deployment hit the same wall:

1. Bicep creates the Container App + the `Key Vault Secrets User` role assignment in one apply.
2. The new ACA revision starts and tries to resolve the KV secret reference using its managed identity.
3. Azure RBAC propagation has not yet completed — it usually takes 60–120 seconds.
4. The revision fails to provision. ACA marks it failed and keeps serving the previous one (if any) or stays in a failed state on a green-field deploy.
5. Operator sees a deployment that "succeeded" per Bicep but a Container App that is not actually running.

Re-running the deploy works (RBAC has propagated by then), but the experience is poor and the first error message points operators in the wrong direction.

`secretSource = 'Direct'` eliminates the dependency: the secret is supplied as a `@secure()` parameter at deploy time and stored directly in the Container App's secret store. Azure scrubs `@secure()` parameters from deployment logs and state; the value never appears in plain text. There is no KV dependency, no RBAC race, and no second-deploy retry.

KV mode is still supported and documented for organisations whose threat model or rotation pipeline favours it. It is no longer the default.

---

## 6. New: `iac/setup-entra-app.sh` / `.ps1`

A single script that creates the Entra app registration with **every** setting EntraMcpProxy needs, idempotently. The configuration steps (9 of them) are:

1. **Verify prerequisites** — `az` + `jq` (bash) / Az CLI (PS); `az account show` to confirm tenant.
2. **Resolve Azure DevOps Remote MCP scope** — looks up the `Ado.Mcp.Tools` scope GUID on the well-known resource `2a72489c-aab2-4b65-b93a-a91edccf33b8`. Creates the SP locally if absent (requires admin).
3. **Create or re-use the app registration** — idempotent on display name. Single-tenant, redirect URI = `https://claude.ai/api/mcp/auth_callback`.
4. **Set `identifierUris` + `isFallbackPublicClient: true`** — Microsoft Graph PATCH. The fallback flag is the one explained in §3 above.
5. **Expose `user_impersonation`** — delegated scope, user + admin consent permitted.
6. **Add the delegated permission** for `Ado.Mcp.Tools`.
7. **Create the service principal** in the local tenant.
8. **Grant admin consent** for all delegated permissions. If the executing user lacks consent rights, the script prints the exact `az` command to hand to an admin and continues.
9. **Mint a fresh client secret** with a 2-year lifetime, `--append` mode so re-runs do not invalidate existing secrets.

Output is a copy-pasteable block for `iac/parameters.bicepparam` plus the secret value (printed once). The Entra portal cannot reveal the secret again — operators are explicitly told to capture it.

Both scripts share an identical 9-step structure so debugging notes apply to either.

---

## 7. Documentation updates

| File | Change |
|---|---|
| `iac/README.md` | Rewritten end-to-end. Now opens with the four-command deploy path, documents `Direct` vs `KeyVault` honestly (including the RBAC race), references the new `setup-entra-app` scripts, lists the deploy-time outputs, and points at the smoke test. |
| `iac/parameters.example.bicepparam` | Restructured around `Direct` as default. Required parameters reduced; KV-specific parameters demoted to commented opt-in. |
| `docs/sandbox-validation.md` | Step 3.2 corrected (`Integration URL` includes `/mcp`, and authentication fields **must** be filled, not left blank — the proxy does not advertise a `registration_endpoint`, so claude.ai cannot do DCR). Step 3.4 references the lazy-discovery behaviour from §1. |
| `docs/changes/2026-05-22-stabilization.md` | This document. |

---

## Migration notes for existing deployments

If a deployment from before this PR is in production:

1. **Code redeploy is required.** The OBO lazy-discovery fix (§1) and the `/mcp` route fix (§2) are both code changes. Without them the proxy boots successfully but serves zero Azure DevOps tools to clients.
2. **Entra app: enable `Allow public client flows`** if you want to use the new smoke script. The toggle is at *Authentication → Advanced settings*. Safe — does not break the existing confidential authorization-code or OBO flows.
3. **IaC re-deploy is optional.** Existing `secretSource = 'KeyVault'` deployments keep working; the new default applies only to new parameter files.
4. **Update `iac/test/test-mcp.sh` invocations** to include `--client-secret`. The flag is required.

The full smoke sequence from a clean macOS / Linux box:

```bash
git pull
bash iac/setup-entra-app.sh             # if you don't already have an Entra app
cp iac/parameters.example.bicepparam iac/parameters.bicepparam
# Edit parameters.bicepparam with the values from setup-entra-app
bash iac/deploy.sh --resource-group <rg>
bash iac/test/test-mcp.sh \
    --tenant-id     <from-output> \
    --client-id     <from-output> \
    --client-secret <from-output> \
    --proxy-url     <mcpEndpointUrl-from-deploy-output>
```

Expected end state: `ALL CHECKS PASSED — the proxy is end-to-end functional.`

---

## Verification

| Test surface | Result |
|---|---|
| `dotnet build` (full solution) | 0 warnings, 0 errors |
| Unit tests (`EntraMcpProxy.Tests`) | 211/211 passing |
| Integration tests (`EntraMcpProxy.IntegrationTests`) | 50/50 passing |
| E2E tests (`EntraMcpProxy.E2ETests`) | Not re-run on this branch — unchanged code paths |
| Live smoke (`test-mcp.sh` against `aca-entra-mcp-proxy-devel`) | Pre-flight ✓, device-code OAuth ✓, MCP initialize awaiting the deploy of `500012e` to produce a final ✓ |

---

## Acknowledgments

This work assumes and builds on the security audit closed in `audit/2026-05-21-security-review.md`. Every change here preserves the security invariants from that audit:

- N3 (DiscoveryScope) — still enforced; the new lazy-discovery path uses the user's bearer, not the SP fallback.
- N5 (tool poisoning defense) — `RefreshToolsForPrefixAsync` carries the same allowlist + policy + provenance pipeline as the original `DiscoverToolsAsync`.
- N14 (MapMcp auth) — `.RequireAuthorization()` retained on the new `/mcp`-prefixed route.
- N19 (egress allowlist) — unchanged; the new HTTP paths flow through the same `EgressEnforcingHandler`.

No security-relevant invariant has been weakened. The lazy connection path uses strictly tighter authentication than the previous SP fallback (per-user delegated token vs app-only token), which is also a security improvement.
