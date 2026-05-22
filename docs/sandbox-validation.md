# EntraMcpProxy — Sandbox Validation Runbook

This runbook lets you empirically confirm that EntraMcpProxy works end-to-end with a
real sandbox Entra tenant and a real claude.ai session **before** you engage a
third-party security reviewer. Execute every step in order. Nothing here touches
production.

---

## Prerequisites

You need:

| Requirement | Notes |
|---|---|
| Azure CLI (`az`) ≥ 2.60 | `az --version`; install from <https://learn.microsoft.com/cli/azure/install-azure-cli> |
| Docker Desktop (or Docker Engine) | `docker --version` |
| An Azure sandbox tenant | Separate from production. You must be a Global Admin or Application Admin in it. |
| A sandbox Azure DevOps organisation | Free org at <https://dev.azure.com> tied to the sandbox tenant. |
| A public HTTPS endpoint | Option A: Azure Container Apps (recommended). Option B: ngrok (local). |
| A claude.ai account with MCP connectors enabled | Pro or Team plan; feature is in Labs settings. |
| PowerShell 7+ or Bash | Either works; commands are shown in Bash syntax. |

Set these shell variables now — they are referenced throughout every command:

```bash
# Replace ALL values before running
export TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # Your sandbox tenant ID
export SUBSCRIPTION_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
export RESOURCE_GROUP="rg-entra-mcp-sandbox"
export LOCATION="eastus"
export APP_NAME="entra-mcp-proxy-sandbox"
export CONTAINER_APP_ENV="cae-sandbox"
export REGISTRY="youracr.azurecr.io"                       # or docker.io/youruser
export IMAGE_TAG="sandbox-$(date +%Y%m%d)"
export PROXY_FQDN=""   # filled in after Container App is created (Step 4)
```

---

## Part 1 — Entra App Registration

### Step 1.1 — Log in and set subscription

```bash
az login --tenant "$TENANT_ID"
az account set --subscription "$SUBSCRIPTION_ID"
```

Verify:

```bash
az account show --query "{tenant:tenantId, sub:id}" -o table
```

Expected: your sandbox tenant ID and subscription ID.

### Step 1.2 — Create the Entra app registration

```bash
az ad app create \
  --display-name "EntraMcpProxy-Sandbox" \
  --sign-in-audience "AzureADMyOrg" \
  --query "{appId:appId, objectId:id}" \
  -o json
```

Capture the output:

```bash
export CLIENT_ID="<appId from above>"
export APP_OBJECT_ID="<objectId from above>"
```

### Step 1.3 — Create a client secret

```bash
az ad app credential reset \
  --id "$CLIENT_ID" \
  --years 1 \
  --query "password" \
  -o tsv
```

Copy the secret immediately — it is not retrievable after this command returns.

```bash
export CLIENT_SECRET="<paste the secret>"
```

### Step 1.4 — Expose a custom API scope (`user_impersonation`)

```bash
# Set the Application ID URI
az ad app update \
  --id "$APP_OBJECT_ID" \
  --identifier-uris "api://$CLIENT_ID"

# Add the user_impersonation scope
az ad app update \
  --id "$APP_OBJECT_ID" \
  --set api.oauth2PermissionScopes='[{
    "adminConsentDescription": "Allows the app to act on behalf of the signed-in user",
    "adminConsentDisplayName": "Act as user",
    "id": "'"$(python3 -c 'import uuid; print(uuid.uuid4())')"'",
    "isEnabled": true,
    "type": "User",
    "userConsentDescription": "Allows the app to act on behalf of you",
    "userConsentDisplayName": "Act as you",
    "value": "user_impersonation"
  }]'
```

### Step 1.5 — Add the redirect URI

```bash
az ad app update \
  --id "$APP_OBJECT_ID" \
  --web-redirect-uris "https://claude.ai/api/mcp/auth_callback"
```

**Enable "Allow public client flows"** — set `isFallbackPublicClient=true`. This is
*orthogonal* to `publicClient` (which we leave false). Setting it does NOT weaken
the proxy's confidential authorization-code / OBO flows; it only additionally
permits the device-code grant that `iac/test/test-mcp.sh` uses for end-to-end
verification. Without it, the smoke script fails post-sign-in with
`AADSTS7000218` even when a valid `client_secret` is supplied — see
[docs/changes/2026-05-22-stabilization.md §3](changes/2026-05-22-stabilization.md)
for the analysis.

```bash
az ad app update \
  --id "$APP_OBJECT_ID" \
  --set isFallbackPublicClient=true
```

(Or simpler: run `bash iac/setup-entra-app.sh` / `pwsh iac/setup-entra-app.ps1`
once and skip every manual `az ad app update` in this section — the script
configures the app registration exactly as documented here.)

### Step 1.6 — Grant Azure DevOps delegated permissions

Look up the Azure DevOps service principal ID in your tenant:

```bash
az ad sp show \
  --id "499b84ac-1321-427f-aa17-267ca6975798" \
  --query "appId" -o tsv
```

Add the delegated `user_impersonation` permission on Azure DevOps:

```bash
az ad app permission add \
  --id "$APP_OBJECT_ID" \
  --api "499b84ac-1321-427f-aa17-267ca6975798" \
  --api-permissions "ee69721e-6c3a-468f-a9ec-302d16a4c599=Scope"
```

Grant admin consent:

```bash
az ad app permission grant \
  --id "$CLIENT_ID" \
  --api "499b84ac-1321-427f-aa17-267ca6975798" \
  --scope "user_impersonation"

az ad app permission admin-consent \
  --id "$CLIENT_ID"
```

### Step 1.7 — Verify the app registration

```bash
az ad app show --id "$APP_OBJECT_ID" \
  --query "{
    appId: appId,
    identifierUris: identifierUris,
    redirectUris: web.redirectUris,
    publicClient: isFallbackPublicClient
  }" -o json
```

Expected output (values will differ):

```json
{
  "appId": "<CLIENT_ID>",
  "identifierUris": ["api://<CLIENT_ID>"],
  "redirectUris": ["https://claude.ai/api/mcp/auth_callback"],
  "publicClient": false
}
```

If `publicClient` is `true`, re-run Step 1.5 before continuing.

---

## Part 2 — Build and Deploy the Proxy

### Step 2.1 — Build the Docker image

From the repo root:

```bash
docker build \
  --tag "$REGISTRY/$APP_NAME:$IMAGE_TAG" \
  --file Dockerfile \
  .
```

### Step 2.2 — Push to a registry

Azure Container Registry:

```bash
az acr login --name "${REGISTRY%%.*}"
docker push "$REGISTRY/$APP_NAME:$IMAGE_TAG"
```

Or Docker Hub:

```bash
docker login
docker push "$REGISTRY/$APP_NAME:$IMAGE_TAG"
```

### Step 2.3 — Create the Resource Group and Container App Environment

```bash
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION"

az containerapp env create \
  --name "$CONTAINER_APP_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"
```

### Step 2.4 — Deploy the Container App

```bash
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINER_APP_ENV" \
  --image "$REGISTRY/$APP_NAME:$IMAGE_TAG" \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 2 \
  --env-vars \
    "ASPNETCORE_ENVIRONMENT=Production" \
    "EntraId__TenantId=$TENANT_ID" \
    "EntraId__ClientId=$CLIENT_ID" \
    "EntraId__ClientSecret=secretref:entrasecret" \
    "Proxy__PublicBaseUrl=https://PLACEHOLDER.azurecontainerapps.io" \
    "Proxy__AllowedRedirectUris__0=https://claude.ai/api/mcp/auth_callback" \
    "Proxy__EgressAllowlist__0=dev.azure.com" \
    "Proxy__EgressAllowlist__1=almsearch.dev.azure.com" \
    "Proxy__DownstreamServers__0__Name=ado" \
    "Proxy__DownstreamServers__0__BaseUrl=https://dev.azure.com/_apis/mcp" \
    "Proxy__DownstreamServers__0__OBO__Scope=499b84ac-1321-427f-aa17-267ca6975798/user_impersonation" \
  --secrets "entrasecret=$CLIENT_SECRET"
```

### Step 2.5 — Capture the public FQDN

```bash
export PROXY_FQDN=$(az containerapp show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" \
  -o tsv)
echo "Proxy public URL: https://$PROXY_FQDN"
```

### Step 2.6 — Update PublicBaseUrl with the real FQDN

The proxy needs `Proxy__PublicBaseUrl` to match the external URL exactly (used in
`WWW-Authenticate` and OIDC discovery).

```bash
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --set-env-vars "Proxy__PublicBaseUrl=https://$PROXY_FQDN"
```

### Step 2.7 — Smoke-test the deployment

```bash
curl -sf "https://$PROXY_FQDN/api/healthz" | python3 -m json.tool
```

Expected: HTTP 200 with a JSON body containing `"status": "healthy"` (or similar).

```bash
curl -sf "https://$PROXY_FQDN/.well-known/oauth-authorization-server" | python3 -m json.tool
```

Expected: JSON document with `authorization_endpoint`, `token_endpoint`, and
`registration_endpoint` pointing at `https://$PROXY_FQDN/...`.

If either check fails, inspect logs before proceeding:

```bash
az containerapp logs show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --follow
```

---

## Part 2B — Alternative: ngrok + Local Docker (no Azure account needed)

Skip this section if you used Container Apps above.

```bash
# Run the proxy locally
docker run -d \
  --name entra-mcp-proxy \
  -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e EntraId__TenantId="$TENANT_ID" \
  -e EntraId__ClientId="$CLIENT_ID" \
  -e EntraId__ClientSecret="$CLIENT_SECRET" \
  -e Proxy__AllowedRedirectUris__0="https://claude.ai/api/mcp/auth_callback" \
  -e Proxy__EgressAllowlist__0="dev.azure.com" \
  -e Proxy__DownstreamServers__0__Name="ado" \
  -e Proxy__DownstreamServers__0__BaseUrl="https://dev.azure.com/_apis/mcp" \
  -e Proxy__DownstreamServers__0__OBO__Scope="499b84ac-1321-427f-aa17-267ca6975798/user_impersonation" \
  -e Proxy__PublicBaseUrl="https://PLACEHOLDER.ngrok-free.app" \
  "$REGISTRY/$APP_NAME:$IMAGE_TAG"

# Start ngrok tunnel (requires a free ngrok account)
ngrok http 8080
```

Copy the `https://*.ngrok-free.app` URL, then update PublicBaseUrl:

```bash
docker stop entra-mcp-proxy && docker rm entra-mcp-proxy
export PROXY_FQDN="<your-ngrok-subdomain>.ngrok-free.app"
docker run -d \
  --name entra-mcp-proxy \
  -p 8080:8080 \
  # ... (same env vars as above, with PublicBaseUrl corrected) ...
  -e Proxy__PublicBaseUrl="https://$PROXY_FQDN" \
  "$REGISTRY/$APP_NAME:$IMAGE_TAG"
```

Smoke-test as in Step 2.7, substituting `$PROXY_FQDN` for the ngrok hostname.

---

## Part 3 — claude.ai Integration

### Step 3.1 — Open the MCP connectors page

1. Navigate to <https://claude.ai>.
2. Click your avatar (top right) → **Settings**.
3. Select **Integrations** (or **Labs** → **Integrations** depending on your plan version).
4. Click **Add integration** (or **Connect apps**).

### Step 3.2 — Add the proxy as a custom integration

- **Integration URL**: `https://$PROXY_FQDN/mcp` (replace `$PROXY_FQDN` literally — the `/mcp` suffix is required; `Program.cs` registers the MCP routes via `MapMcp("/mcp")`)
- **Client ID**: your `entraClientId`
- **Client Secret**: the same secret value you supplied to the IaC at deploy time (printed once by `iac/setup-entra-app.sh|.ps1`)

You **must** fill the client ID and secret. The proxy does not advertise a `registration_endpoint` in its OAuth discovery document, so claude.ai cannot fall back to Dynamic Client Registration — it needs static credentials. The proxy's `/token` endpoint is a transparent relay to Entra ([`Program.cs:435-476`](../Program.cs)), so the credentials you provide here are what Entra evaluates.

Click **Save** (or **Add**).

### Step 3.3 — Complete the OAuth flow

claude.ai will redirect you to the proxy's `/authorize` endpoint, which in turn
redirects you to Entra's real login page.

1. Sign in with a sandbox user account (must be in the sandbox tenant).
2. Consent to the `user_impersonation` scope if prompted.
3. You are redirected back to claude.ai.

Expected: the integration shows a green "Connected" status.

### Step 3.4 — Verify tool discovery

Start a new claude.ai conversation and type:

> "What tools do you have available from the MCP integration?"

Expected: Claude lists tools served by the Azure DevOps Remote MCP (e.g. `azdevops__list_projects`, `azdevops__list_repos`).

**On first-use latency:** the first authenticated `tools/list` triggers lazy discovery against Azure DevOps in the calling user's context (the background loop cannot do this — Azure DevOps Remote MCP is user-delegated only). The first interaction has an extra round-trip; subsequent calls hit the cached registry and return instantly. See [docs/changes/2026-05-22-stabilization.md §1](changes/2026-05-22-stabilization.md) for the architecture.

If Claude reports no tools after the first interaction, check Part 2 Step 2.7 and the container logs.

---

## Part 4 — Compatibility Test Scenarios

For each scenario below: perform the action described, observe the result, compare
against the pass criterion. Record pass or fail in the final checklist.

---

### Scenario 1 — Basic OAuth authorization flow completes

**Action**: Start a fresh browser session (private/incognito). Add the MCP
integration in claude.ai as in Part 3 and complete the OAuth flow.

**Pass criterion**: claude.ai shows "Connected" and the proxy audit log contains an
`oauth_token_issued` event (or equivalent) with no errors.

**Fail — most likely cause**: `redirect_uri` mismatch. Verify that the Entra app
registration's redirect URI is exactly `https://claude.ai/api/mcp/auth_callback`
(no trailing slash, exact case). Re-run Step 1.5 if needed.

---

### Scenario 2 — Tool list is returned to claude.ai

**Action**: In a new conversation, ask Claude to list available tools.

**Pass criterion**: Claude returns at least one tool name without an error message
or "I don't have any tools" response.

**Fail — most likely cause**: The proxy cannot reach the downstream MCP. Check
`Proxy__EgressAllowlist__0` includes `dev.azure.com`. Inspect logs for
`egress_blocked` events.

---

### Scenario 3 — Tool call succeeds end-to-end

**Action**: Ask Claude to run a real Azure DevOps tool call, e.g.:
> "List the repositories in my organisation using the ADO tools."

**Pass criterion**: Claude returns real ADO data (not an error). The proxy audit log
shows a `tool_invocation` event with `status: "success"`.

**Fail — most likely cause**: OBO exchange failure. Verify the `OBO__Scope` matches
the permission granted in Step 1.6. Check that admin consent was granted (Step 1.6
last command).

---

### Scenario 4 — Second user gets their own token (no cross-contamination)

**Action**: In a second browser profile signed in as a different sandbox user,
connect the same MCP integration and invoke a tool that returns user-specific data
(e.g., list work items assigned to me).

**Pass criterion**: Each user sees their own data. The proxy audit log shows two
distinct `oid` values across the two sessions' tool invocation events.

**Fail — most likely cause**: OBO cache keyed on wrong field. Check for `C1`/`C2`
findings in the audit trail — the `OboCacheKey` should include both `oid` and
`tid`.

---

### Scenario 5 — Session disconnect and reconnect

**Action**: Disconnect the integration in claude.ai Settings. Re-add it. Complete
the OAuth flow again.

**Pass criterion**: The second OAuth flow completes without error. New tokens are
issued. The proxy does not serve a stale cached token from the previous session.

**Fail — most likely cause**: Token lifetime issue. Verify that `expires_in` in the
OBO response is respected and the cache is not serving tokens past their expiry.

---

### Scenario 6 — Token expiry and transparent refresh

**Action**: Issue a tool call immediately after the OBO token has expired. (You can
force this in a sandbox by setting a very short token lifetime via Entra's token
lifetime policy, or simply wait for the default 1-hour lifetime.)

**Pass criterion**: Claude continues to work after expiry. The proxy transparently
issues a new OBO exchange. The old token is not used after expiry.

**Fail — most likely cause**: The OBO cache is not checking expiry. Inspect the
`OboCacheKey` and related token expiry logic in `Services/EntraIdOBOHandler.cs`.

---

### Scenario 7 — Unauthorized tool call is blocked

**Action**: Configure `Proxy:Authorization:Tools` in the proxy's env vars to
restrict access to one tool. Attempt to call a tool that is NOT on the allowed list
via Claude.

Example env var to add:

```bash
Proxy__Authorization__Tools__0__ToolPattern="ado_list_repos"
Proxy__Authorization__Tools__0__AllowedGroups__0="00000000-0000-0000-0000-000000000001"
```

Then attempt `ado_get_work_items` (which is not in the `ToolPattern`).

**Pass criterion**: Claude reports that the tool is not available or returns an
access denied message. The proxy audit log shows an `authz_denied` event.

**Fail — most likely cause**: Authorization policy not loaded. Verify the
`Proxy:Authorization:Tools` config key is being read. Restart the proxy after
updating env vars.

---

### Scenario 8 — Proxy restart does not break in-flight sessions

**Action**: While a claude.ai conversation is active and the MCP integration
shows "Connected", restart the proxy container:

```bash
az containerapp revision restart \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP"
# or: docker restart entra-mcp-proxy
```

Wait 30 seconds, then issue a tool call in the same claude.ai conversation.

**Pass criterion**: After the restart, claude.ai reconnects (may show a brief
disconnect) and the next tool call succeeds without requiring the user to
re-authenticate.

**Fail — most likely cause**: The proxy's OBO cache is in-memory only — after
restart the cache is empty and a new OBO exchange is needed. This is expected
behaviour; the fail condition is if the OAuth flow itself breaks (returns 5xx
rather than prompting re-auth).

---

## Part 5 — Security Probe Scenarios

For each probe: run the curl command exactly as shown (substituting `$PROXY_FQDN`),
observe the HTTP status code and response body, compare to the pass criterion.

---

### Probe 1 — Redirect URI not in allowlist is rejected

```bash
curl -v "https://$PROXY_FQDN/authorize?\
response_type=code\
&client_id=$CLIENT_ID\
&redirect_uri=https%3A%2F%2Fattacker.example.com%2Fcallback\
&state=xyz\
&code_challenge=abcdefghijklmnopqrstuvwxyz012345abcdefghijklm\
&code_challenge_method=S256" 2>&1 | grep -E "^< HTTP|error"
```

**Pass criterion**: HTTP `400 Bad Request`. Response body contains `invalid_request`
or `redirect_uri_rejected`. Must NOT be a 302 redirect to attacker.example.com.

**Fail — most likely cause**: `Proxy:AllowedRedirectUris` is empty or not loaded.
Check the env var `Proxy__AllowedRedirectUris__0` is set to
`https://claude.ai/api/mcp/auth_callback`.

---

### Probe 2 — PKCE omitted is rejected

```bash
curl -v "https://$PROXY_FQDN/authorize?\
response_type=code\
&client_id=$CLIENT_ID\
&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback\
&state=xyz" 2>&1 | grep -E "^< HTTP|error"
```

(Note: no `code_challenge` or `code_challenge_method` parameters.)

**Pass criterion**: HTTP `400 Bad Request`. Response body contains `pkce_missing`
or `invalid_request`. Must NOT proceed to Entra login.

**Fail — most likely cause**: PKCE enforcement not active. Check `PkceValidator` is
wired in the `/authorize` handler.

---

### Probe 3 — Rate limiting kicks in at 31 requests per minute

Send 31 POST requests to `/token` in rapid succession from one IP:

```bash
for i in $(seq 1 31); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://$PROXY_FQDN/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=fake&code_verifier=fake")
  echo "Request $i: $STATUS"
done
```

**Pass criterion**: Requests 1–30 return any status code other than 429. Request 31
returns `429 Too Many Requests`.

**Fail — most likely cause**: `Proxy:RateLimit:RequestsPerMinute` default is 30 but
the container was deployed without the setting. Verify the env var
`Proxy__RateLimit__RequestsPerMinute` is set (defaults to 30 if absent).

---

### Probe 4 — Unauthenticated MCP tool call is rejected

```bash
curl -v -X POST "https://$PROXY_FQDN/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  2>&1 | grep -E "^< HTTP"
```

**Pass criterion**: HTTP `401 Unauthorized` with a `WWW-Authenticate: Bearer ...`
header. No tool list is returned.

**Fail — most likely cause**: The `/mcp` route is not protected by JWT validation.
Verify `MapMcp` is called after `UseAuthentication` + `UseAuthorization` in
`Program.cs`.

---

### Probe 5 — Oversized token body is rejected

```bash
# Generate a 65 KB body (well above the 8 KB limit)
BIGBODY=$(python3 -c "print('a=' + 'x'*65536)")
curl -v -X POST "https://$PROXY_FQDN/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$BIGBODY" \
  2>&1 | grep -E "^< HTTP"
```

**Pass criterion**: HTTP `413 Request Entity Too Large` (or `400`). The proxy does
not forward the oversized body to Entra.

**Fail — most likely cause**: Body size limit not configured. Check that
`AddRequestSizeLimiting` is applied to the `/token` route in `Program.cs`.

---

### Probe 6 — Arbitrary host header does not change discovery URLs

```bash
curl -s "https://$PROXY_FQDN/.well-known/oauth-authorization-server" \
  -H "Host: evil.attacker.com" \
  -H "X-Forwarded-Host: evil.attacker.com" | python3 -m json.tool | grep -E "endpoint|issuer"
```

**Pass criterion**: All URLs in the response contain `$PROXY_FQDN`, NOT
`evil.attacker.com`. The `X-Forwarded-Host` header must not influence the response.

**Fail — most likely cause**: `UseForwardedHeaders` is still active or
`PublicBaseUrlAccessor` is reading `Host` instead of the configured
`Proxy:PublicBaseUrl`. Check that `UseForwardedHeaders` is removed from
`Program.cs` (finding H5).

---

## Part 6 — Pass/Fail Checklist

Complete this checklist after executing all scenarios and probes. Do not proceed to
third-party review until every item is checked.

### Compatibility scenarios

- [ ] **Scenario 1** — Basic OAuth authorization flow completes
- [ ] **Scenario 2** — Tool list is returned to claude.ai
- [ ] **Scenario 3** — Tool call succeeds end-to-end
- [ ] **Scenario 4** — Second user gets their own token (no cross-contamination)
- [ ] **Scenario 5** — Session disconnect and reconnect
- [ ] **Scenario 6** — Token expiry and transparent refresh
- [ ] **Scenario 7** — Unauthorized tool call is blocked
- [ ] **Scenario 8** — Proxy restart does not break in-flight sessions

### Security probes

- [ ] **Probe 1** — Redirect URI not in allowlist → HTTP 400
- [ ] **Probe 2** — PKCE omitted → HTTP 400
- [ ] **Probe 3** — 31st request in 60 s → HTTP 429
- [ ] **Probe 4** — Unauthenticated MCP call → HTTP 401
- [ ] **Probe 5** — Oversized token body → HTTP 413
- [ ] **Probe 6** — Arbitrary Host header does not poison discovery URLs

### Infrastructure

- [ ] `/api/healthz` returns HTTP 200 in steady state
- [ ] `EntraMcpProxy.Audit` log events visible in your log sink (not just stdout)
- [ ] Prometheus `/metrics` endpoint returns data (if scraping is configured)
- [ ] Container restarts automatically on crash (at least 1 replica)

---

## Part 7 — Teardown

After all scenarios pass, clean up the sandbox resources:

```bash
az group delete --name "$RESOURCE_GROUP" --yes --no-wait
az ad app delete --id "$APP_OBJECT_ID"
```

If you used ngrok, stop the tunnel and the Docker container:

```bash
docker stop entra-mcp-proxy && docker rm entra-mcp-proxy
# Ctrl-C the ngrok process
```

---

## Appendix — Interpreting Audit Log Events

After each scenario, check the structured audit log for the expected events. If you
deployed to Container Apps:

```bash
az containerapp logs show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --tail 100 | grep EntraMcpProxy.Audit
```

Key events to look for:

| Event | Scenario | Meaning |
|---|---|---|
| `oauth_authorize_started` | 1, 5 | `/authorize` received a valid request |
| `oauth_token_issued` | 1, 5 | `/token` returned a token |
| `tool_invocation` | 3, 7, 8 | A tool call was proxied downstream |
| `authz_denied` | 7 | Per-tool authorization blocked the call |
| `pkce_missing` | Probe 2 | PKCE enforcement fired |
| `redirect_uri_rejected` | Probe 1 | Redirect URI not in allowlist |
| `obo_exchange_failed` | (should not appear) | OBO failure — investigate |

If you see `obo_exchange_failed` events in normal operation (Scenarios 1–8),
investigate before proceeding to third-party review. The most common causes are:
an expired `client_secret`, missing admin consent, or an incorrect `OBO__Scope`.
