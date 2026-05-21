# Incident Runbook — Proxy Auth Outage

**Severity**: High (user-facing — no one can use claude.ai MCP integration)
**Target time-to-mitigation**: 30 minutes from detection
**Owner**: Application on-call

An auth outage means the proxy stops accepting authentication requests:
- `/authorize` returns 5xx or no response
- `/token` returns 5xx or authentication fails
- Every `/mcp` call returns 401 even for recently-authenticated users
- claude.ai shows "Disconnected" or "Authentication failed" for the MCP connector

---

## Symptoms

| Symptom | Likely layer |
|---|---|
| Every `/mcp` returns 401; `/api/healthz` also fails | Container is down |
| Every `/mcp` returns 401; `/api/healthz` returns 200 | JWT validation failure |
| `/authorize` redirects to Entra but Entra returns error | Entra configuration issue |
| `/token` returns 401 or `invalid_client` | `client_secret` mismatch or expired |
| `/token` returns 500 | Proxy bug or Entra unreachable |
| claude.ai shows "integration error" but `/api/healthz` is 200 | claude.ai-side issue |

---

## Triage Flow

```
Start
  |
  v
Is /api/healthz returning HTTP 200?
  |
  +-- No  --> [Step 1] Container is down. Go to Container Down section.
  |
  +-- Yes
       |
       v
     Is /authorize reachable?
       |
       +-- No (5xx/timeout) --> [Step 2] App startup error. Go to App Error section.
       |
       +-- Yes (redirects to Entra login)
            |
            v
          Does the OAuth flow complete successfully?
            |
            +-- No (Entra returns error)   --> [Step 3] Entra config issue. See below.
            |
            +-- No (callback fails)         --> [Step 4] Redirect URI or client_secret issue.
            |
            +-- Yes (flow completes)
                 |
                 v
               Does the /mcp call with the token return 200?
                 |
                 +-- No (401)  --> [Step 5] JWT validation issue.
                 +-- No (5xx)  --> [Step 6] Downstream or OBO issue.
                 +-- Yes       --> Intermittent issue. Check Grafana for patterns.
```

---

## Step 1 — Container Is Down

`/api/healthz` returns non-200 or times out.

Check container status:

```bash
# Container Apps
az containerapp show \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --query "properties.runningStatus" -o tsv

# Kubernetes
kubectl get pods -l app=entra-mcp-proxy
kubectl describe pod <pod-name>
```

Get recent logs:

```bash
# Container Apps
az containerapp logs show \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --tail 100

# Kubernetes
kubectl logs <pod-name> --previous
```

Common causes:
- **OOMKilled**: container ran out of memory. Increase memory limit.
- **CrashLoopBackOff**: application exception on startup. Look for config validation
  errors in the logs (the startup validator will log them as errors).
- **Image pull error**: registry credentials expired or image digest changed.

Fix for image pull error:

```bash
# Re-authenticate to the registry
az acr login --name "<registry-name>"
# Or update the image pull secret in Kubernetes
```

Restart the deployment:

```bash
# Container Apps
az containerapp revision restart \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>"

# Kubernetes
kubectl rollout restart deployment/entra-mcp-proxy
```

---

## Step 2 — App Startup Error

`/api/healthz` is 200 but `/authorize` returns 500.

Check startup logs for config validation errors:

```bash
az containerapp logs show \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --tail 200 | grep -E "ERROR|CRIT|fail|exception" -i
```

Common causes:
- `Proxy:PublicBaseUrl` is not a valid HTTPS URL
- `Proxy:AllowedRedirectUris` is empty
- `EntraId:Authority` points at the wrong tenant
- A new env var introduced a parse error

Fix: correct the offending env var and restart.

---

## Step 3 — Entra Returns Error on Authorize

The user is redirected to Entra's login page but Entra shows an error.

Check Entra sign-in logs in Azure Portal → Entra ID → Sign-in logs.

Common Entra errors:

| Entra error | Meaning | Fix |
|---|---|---|
| `AADSTS70011` | Invalid scope | `OBO__Scope` in config does not match a scope exposed by the app registration |
| `AADSTS50011` | Reply URL mismatch | Redirect URI in the request does not match the app registration allowlist |
| `AADSTS700016` | App not found | `CLIENT_ID` is wrong or the app registration was deleted |
| `AADSTS90002` | Tenant not found | `TENANT_ID` is wrong or the tenant was deprovisioned |

```bash
# Verify the current Entra authority config resolves
curl -s "https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration" | python3 -m json.tool | grep issuer
```

---

## Step 4 — OAuth Callback Fails / `invalid_client` at `/token`

The user completes Entra login but the callback to `/token` fails.

Diagnose by checking the `/token` response body:

```bash
curl -v -X POST "https://$PROXY_FQDN/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=dummy&code_verifier=dummy&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback" \
  2>&1 | tail -30
```

Common causes:

**`invalid_client`**: The `client_secret` in the proxy's env var does not match
what is registered in Entra. This happens after a secret rotation if the proxy was
not redeployed.

```bash
# Check when the current secret was created in Entra
az ad app credential list --id "<CLIENT_ID>" \
  --query "[].{keyId:keyId,displayName:displayName,endDate:endDateTime}" -o table
```

Fix: verify the secret in the secrets store matches the Entra app registration.
Rotate if necessary (see `runbook-secret-leak.md` Step 7).

**`expired_secret`**: The `client_secret` has passed its expiry date.

Fix: create a new secret (Step 7 of `runbook-secret-leak.md`), update the secrets
store, redeploy.

```bash
# Quick check: is the secret expired?
az ad app credential list --id "<CLIENT_ID>" \
  --query "[].{keyId:keyId, endDate:endDateTime}" -o table
# Compare endDate to today's date
```

---

## Step 5 — JWT Validation Failure (`/mcp` returns 401)

The user has a token but the proxy rejects it.

Check proxy logs for JWT validation errors:

```bash
az containerapp logs show \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --tail 100 | grep -i "jwt\|bearer\|401\|unauthorized" -i
```

Verify Entra is reachable from inside the container:

```bash
# Exec into the container (Container Apps)
az containerapp exec \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --command "curl -s https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys | head -c 200"

# Kubernetes
kubectl exec -it <pod-name> -- curl -s https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys | head -c 200
```

Expected: a JSON response with `keys` array. If this times out, the container
cannot reach Entra — check network policy / egress firewall rules.

Common causes:
- Entra JWKS endpoint unreachable from the container network (egress blocked)
- `EntraId:Authority` points at wrong tenant — JWKS issuer will not match
- Clock skew > 5 minutes between container and NTP (JWT `nbf`/`exp` validation fails)

```bash
# Check container time
az containerapp exec --name "<APP_NAME>" --resource-group "<RESOURCE_GROUP>" \
  --command "date -u"
# Compare to UTC now
```

---

## Step 6 — OBO or Downstream Error (`/mcp` returns 5xx)

The JWT is valid but the proxy fails when forwarding the tool call.

Check OBO error audit events:

```kql
traces
| where customDimensions.log_category == "EntraMcpProxy.Audit"
| where customDimensions.event_type == "obo_exchange_failed"
| project timestamp, customDimensions.oid, customDimensions.error
| order by timestamp desc
| take 20
```

Common OBO errors:

| Error | Meaning | Fix |
|---|---|---|
| `invalid_grant` | User's token cannot be exchanged (revoked session, MFA required) | User must re-authenticate |
| `invalid_client` | `client_secret` mismatch | Same as Step 4 |
| `AADSTS65001` | User has not consented to the scope | Re-run admin consent (`az ad app permission admin-consent`) |
| `AADSTS50076` | MFA required by Conditional Access | Ensure the user's session satisfies MFA requirements |

---

## Rollback Plan

If a recent deployment caused the outage, roll back to the previous image:

```bash
# Container Apps — list revisions and activate the previous one
az containerapp revision list \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --query "[?properties.active==\`false\`].{name:name, created:properties.createdTime}" \
  -o table

az containerapp revision activate \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --revision "<previous-revision-name>"

# Then deactivate the broken revision
az containerapp revision deactivate \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --revision "<broken-revision-name>"
```

Kubernetes:

```bash
kubectl rollout undo deployment/entra-mcp-proxy
kubectl rollout status deployment/entra-mcp-proxy
```

---

## Post-Incident Actions

Complete within 24 hours of restoration:

- [ ] Root cause documented in incident ticket
- [ ] Duration of outage recorded (start time, end time, affected user count)
- [ ] Users notified of outage and resolution (if customer-facing SLA exists)
- [ ] Alert rule reviewed — did the `EntraMcpProxyDown` or latency alert fire in
  time? If not, tune thresholds in `monitoring/prometheus-alerts.yml`.
- [ ] If caused by secret expiry: add calendar reminder for next rotation
- [ ] If caused by Entra connectivity: add an egress connectivity health check to
  the proxy's health endpoint
- [ ] Runbook updated if any steps were unclear or missing
- [ ] Post-incident review meeting scheduled within 5 business days

---

## Escalation

| Trigger | Escalate to |
|---|---|
| Outage > 30 minutes with no root cause identified | `[OPERATOR-FILL: Engineering manager / VP Eng]` |
| Entra service outage (not your config) | `[OPERATOR-FILL: Azure support ticket + Microsoft status page]` |
| claude.ai-side issue | `[OPERATOR-FILL: Anthropic enterprise support contact]` |
| SLA breach (if applicable) | `[OPERATOR-FILL: Customer success + Legal]` |
