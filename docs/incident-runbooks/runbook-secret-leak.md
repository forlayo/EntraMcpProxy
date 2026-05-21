# Incident Runbook — Suspected `client_secret` Leak

**Severity**: Critical
**Target time-to-containment**: 30 minutes from detection
**Owner**: Security on-call + Azure admin on-call

---

## Symptoms

Any ONE of the following should trigger this runbook:

- Anthropic notifies you that MCP connector credentials may have been exposed in a
  security incident on their infrastructure.
- You observe `/token` audit events for `oid` values that are NOT your users (or
  events at unusual hours / from unusual IPs).
- You observe a spike in `oauth_rejections_total` or unusual `oauth_token_issued`
  volume in Grafana.
- The `client_secret` appears in a secrets-scanning alert (GitHub secret scanning,
  Gitleaks, Trufflehog, etc.).
- A team member reports they saw the secret in a log, error message, or Slack post.

---

## Immediate Actions (first 5 minutes)

**Step 1** — Invalidate the compromised secret in Entra immediately:

```bash
# Get the credential IDs for the app registration
az ad app credential list --id "<CLIENT_ID>" --query "[].{keyId:keyId, displayName:displayName}" -o table

# Delete ALL existing secrets (safest — create a new one right after)
CREDENTIAL_ID="<keyId of the compromised credential>"
az ad app credential delete --id "<CLIENT_ID>" --key-id "$CREDENTIAL_ID"
```

If you are not sure which credential is compromised, delete all credentials:

```bash
az ad app credential list --id "<CLIENT_ID>" --query "[].keyId" -o tsv | while read KID; do
  az ad app credential delete --id "<CLIENT_ID>" --key-id "$KID"
done
```

Token revocation: existing tokens issued before this moment will remain valid until
they expire (default 1 hour for Entra access tokens). For immediate user-level
revocation, use Entra's user sign-in revocation:

```bash
# Revoke all sessions for a specific user (use if you know which users are affected)
az ad user revoke-sign-in-sessions --id "<user-upn-or-oid>"

# For tenant-wide revocation (drastic — use only if breach is broad)
# Raise a ticket with your Entra Global Admin — this requires Global Admin privileges
```

**Step 2** — Open a major incident ticket now, while performing the above:

```
Incident title: Suspected client_secret leak — EntraMcpProxy
Severity: Critical
IC: <your name>
Time opened: <timestamp>
```

**Step 3** — Notify your security team and management per your incident response
policy. Do NOT wait until containment to notify.

---

## Diagnosis Steps

**Step 4** — Determine the leak window:

Query your audit log sink for the period before you invalidated the secret.

Azure Monitor / Log Analytics KQL:

```kql
traces
| where customDimensions.log_category == "EntraMcpProxy.Audit"
| where customDimensions.event_type == "oauth_token_issued"
| project timestamp, customDimensions.oid, customDimensions.tid, customDimensions.client_id
| order by timestamp desc
```

Look for:
- `oid` values not belonging to your known users
- Unusual timestamps (outside business hours)
- High volume bursts

**Step 5** — Check Entra sign-in logs for the proxy's `client_id`:

1. Navigate to Azure Portal → Entra ID → Sign-in logs
2. Filter by Application: `<CLIENT_ID>`
3. Look for sign-in events you did not initiate (IP addresses outside your expected
   range, unusual user agents)

```bash
# CLI query for sign-ins (requires Microsoft Graph permissions)
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=appId eq '<CLIENT_ID>'&\$top=50" \
  --headers "Content-Type=application/json"
```

**Step 6** — Identify how the secret was exposed:

Common vectors:
- Secret committed to git (`git log -p | grep -i secret`)
- Secret in container environment variables visible in a log or CI output
- Secret in an error message / exception dump
- Anthropic infrastructure breach (in which case Anthropic should notify you)

Document the root cause before closing the incident.

---

## Containment: Issue a New Secret

**Step 7** — Create a new `client_secret`:

```bash
az ad app credential reset \
  --id "<CLIENT_ID>" \
  --years 1 \
  --query "password" \
  -o tsv
# Copy the new secret immediately
NEW_SECRET="<paste here>"
```

**Step 8** — Update the secret in your secrets store:

Azure Key Vault:

```bash
az keyvault secret set \
  --vault-name "<your-vault>" \
  --name "entra-mcp-proxy-client-secret" \
  --value "$NEW_SECRET"
```

Kubernetes secret:

```bash
kubectl create secret generic entra-mcp-proxy-secret \
  --from-literal=client_secret="$NEW_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Step 9** — Redeploy the proxy so it picks up the new secret:

Container Apps:

```bash
az containerapp update \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --set-env-vars "EntraId__ClientSecret=secretref:entrasecret"
# If using a secret reference, update the secret value in Container Apps:
az containerapp secret set \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --secrets "entrasecret=<NEW_SECRET>"
az containerapp revision restart \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>"
```

Kubernetes:

```bash
kubectl rollout restart deployment/entra-mcp-proxy
```

**Step 10** — Verify the proxy is accepting auth again:

```bash
curl -sf "https://$PROXY_FQDN/api/healthz"
# Expected: HTTP 200

# Then test a real OAuth flow or use the sandbox validation runbook Scenario 1
```

---

## Rollback Plan

If the new deployment fails to start:

```bash
# Revert to the previous image revision (Container Apps)
az containerapp revision list \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --query "[].{name:name, active:properties.active, created:properties.createdTime}" \
  -o table

az containerapp revision activate \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --revision "<previous-revision-name>"
```

Note: the previous revision will use the old (now-invalidated) `client_secret` and
will NOT be able to issue new tokens. This is acceptable as a temporary state — the
proxy will still serve cached OBO tokens until they expire, and no new auth flows
will succeed until the new secret is deployed.

---

## Post-Incident Actions

Complete within 48 hours of containment:

- [ ] Root cause documented in the incident ticket
- [ ] Blast radius assessment: which users' sessions may have been accessed
  during the leak window? Contact affected users if data access is confirmed.
- [ ] Entra sign-in logs exported and archived (evidence preservation)
- [ ] Audit log exported and archived for the leak window
- [ ] Notify affected users per your breach notification policy (GDPR 72-hour
  window if applicable)
- [ ] Notify Anthropic if the leak originated on their infrastructure:
  security@anthropic.com
- [ ] Update the `client_secret` expiry in the rotation tracker
- [ ] Root cause fix implemented (e.g., remove secret from git history, fix CI log
  filtering)
- [ ] Runbook updated if any steps were unclear or missing
- [ ] Post-incident review meeting scheduled within 5 business days

---

## Escalation

| Trigger | Escalate to |
|---|---|
| Cannot reach Azure Portal or CLI | `[OPERATOR-FILL: Azure admin contact]` |
| Breach involves financial reporting data | `[OPERATOR-FILL: CISO + Legal]` |
| Anthropic has not responded within 4 hours | `[OPERATOR-FILL: Anthropic enterprise support contact]` |
| Entra tenant admin access required | `[OPERATOR-FILL: Global Admin contact]` |
