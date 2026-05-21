# Incident Runbook — Suspected Downstream MCP Compromise

**Severity**: High–Critical (depends on scope)
**Target time-to-containment**: 60 minutes from detection
**Owner**: Security on-call + application owner

A "downstream MCP compromise" means one of the configured downstream MCP servers
(e.g., Azure DevOps Remote MCP at `dev.azure.com/_apis/mcp`) is serving malicious
tool metadata, malicious tool results, or acting outside its expected behaviour.

---

## Symptoms

Any ONE of the following:

- Unexpected `tool_set_changed` audit event: tools appearing in or disappearing from
  the catalog that were not deployed by your team.
- Tool descriptions contain unexpected content (e.g., instructions to the model to
  exfiltrate data, new `$ref` URLs pointing to external hosts).
- Claude begins performing actions that neither the user nor your organisation
  authorised (lateral movement, unusual ADO API calls).
- The downstream MCP returns HTTP 5xx or unusual error patterns at elevated rates.
- External security advisory for Azure DevOps Remote MCP or the downstream MCP you
  have configured.
- `obo_exchanges_total{outcome="error"}` spike: the downstream may be rejecting
  tokens it would normally accept, indicating a change in its authentication
  requirements.

---

## Immediate Actions (first 15 minutes)

**Step 1** — Disable the affected downstream server in config:

The fastest isolation is to set `Enabled: false` on the affected downstream and
redeploy. This causes the proxy to return an empty tool list to claude.ai for that
downstream, stopping all tool calls.

```bash
# Container Apps: set env var and restart
az containerapp update \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --set-env-vars "Proxy__DownstreamServers__0__Enabled=false"

az containerapp revision restart \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>"
```

Kubernetes / docker-compose: update `appsettings.Production.json` or the env var
equivalent, then roll the deployment.

**Step 2** — Verify the downstream is isolated:

```bash
# Tool list should now be empty for the affected downstream
curl -s -H "Authorization: Bearer <valid-user-token>" \
  "https://$PROXY_FQDN/mcp" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  -H "Content-Type: application/json" | python3 -m json.tool
# Expected: tools array is empty (or only contains tools from non-affected downstreams)
```

**Step 3** — Open a major incident ticket:

```
Incident title: Suspected downstream MCP compromise — [downstream name]
Severity: High
IC: <your name>
Time opened: <timestamp>
Affected downstream: <name and BaseUrl>
```

---

## Diagnosis Steps

**Step 4** — Extract tool invocation audit events for the suspected compromise
window:

Azure Monitor KQL:

```kql
traces
| where customDimensions.log_category == "EntraMcpProxy.Audit"
| where customDimensions.event_type == "tool_invocation"
| where customDimensions.downstream == "<affected-downstream-name>"
| where timestamp >= datetime(<start-of-window>) and timestamp <= datetime(<end-of-window>)
| project timestamp, customDimensions.tool_name, customDimensions.oid,
          customDimensions.tid, customDimensions.status
| order by timestamp desc
```

Look for:
- Users who invoked the affected tools during the window
- Unusual tool names (tools added by the compromise)
- `status: "exception"` spikes (malformed responses from the downstream)

**Step 5** — Check `tool_set_changed` events:

```kql
traces
| where customDimensions.log_category == "EntraMcpProxy.Audit"
| where customDimensions.event_type == "tool_set_changed"
| where customDimensions.downstream == "<affected-downstream-name>"
| project timestamp, customDimensions.added_tools, customDimensions.removed_tools
| order by timestamp desc
```

If `added_tools` contains unexpected entries, those tools may be the attack vector.

**Step 6** — Review the current tool catalog from the downstream (do this from a
safe environment — not through the proxy):

```bash
# Direct probe of the downstream (bypasses the proxy's protections — use carefully)
# Only do this if you have credentials and it is safe to contact the downstream directly
curl -s -H "Authorization: Bearer <sp-token-for-discovery>" \
  "https://dev.azure.com/_apis/mcp/tools/list" | python3 -m json.tool
```

Compare against the last known-good tool catalog (check git history or a saved
snapshot if available).

**Step 7** — Contact the downstream vendor:

For Azure DevOps Remote MCP:
- Check [status.dev.azure.com](https://status.dev.azure.com) for active incidents.
- File a support ticket via the Azure portal if you believe the MCP endpoint itself
  is compromised.

For a self-hosted downstream MCP:
- Contact the team that owns the downstream.
- Check their deployment history for unexpected changes.

---

## Containment and Recovery

**Step 8** — Assess the blast radius:

For each user identified in Step 4:
- What tools did they call?
- What data did those tools expose?
- Did any tool calls result in write operations (creating work items, pushing code)?
  If so, those changes should be audited and potentially reversed.

Contact affected users if their data may have been exposed to the compromised
downstream.

**Step 9** — Restore from a known-good downstream version:

If you operate the downstream yourself, roll it back:

```bash
# Kubernetes rollback example
kubectl rollout undo deployment/<downstream-mcp-deployment>
kubectl rollout status deployment/<downstream-mcp-deployment>
```

If the downstream is a Microsoft service (Azure DevOps Remote MCP), wait for
Microsoft to remediate or switch to a different API endpoint if available.

**Step 10** — Re-enable the downstream with restricted `AllowedTools`:

After confirming the downstream is clean, re-enable it with the minimum required
tool set:

Update `Proxy:DownstreamServers:0:AllowedTools` in your config to the explicitly
approved list before re-enabling.

```bash
# Example: re-enable with explicit tool allowlist
az containerapp update \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --set-env-vars \
    "Proxy__DownstreamServers__0__Enabled=true" \
    "Proxy__DownstreamServers__0__AllowedTools__0=ado_list_repos" \
    "Proxy__DownstreamServers__0__AllowedTools__1=ado_get_work_items"

az containerapp revision restart \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>"
```

**Step 11** — Verify tool discovery after re-enabling:

```bash
curl -s -H "Authorization: Bearer <valid-user-token>" \
  "https://$PROXY_FQDN/mcp" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  -H "Content-Type: application/json" | python3 -m json.tool
# Expected: only the tools in AllowedTools are returned
```

---

## Rollback Plan

If re-enabling the downstream causes new issues, disable again immediately:

```bash
az containerapp update \
  --name "<APP_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --set-env-vars "Proxy__DownstreamServers__0__Enabled=false"
```

The proxy continues to function for other downstreams; only the affected one is
offline.

---

## Post-Incident Actions

Complete within 72 hours of containment:

- [ ] Root cause documented: was this a misconfiguration, a supply chain attack, a
  vendor incident, or something else?
- [ ] Blast radius report completed: which users, which data, which time window
- [ ] Affected users notified if data exposure is confirmed
- [ ] Vendor notified (Microsoft for Azure DevOps Remote MCP) if the compromise
  originated on their side
- [ ] `AllowedTools` config updated to principle-of-least-privilege list (if not
  already done in Step 10)
- [ ] `tool_set_changed` alerting reviewed — should this alert have fired earlier?
  If not, tune the alerting rules in `monitoring/prometheus-alerts.yml`
- [ ] Snapshot of known-good tool catalog archived for future comparison
- [ ] Runbook updated if any steps were unclear or missing
- [ ] Post-incident review meeting scheduled within 5 business days

---

## Escalation

| Trigger | Escalate to |
|---|---|
| Compromise involves customer PII | `[OPERATOR-FILL: CISO + Legal + DPO]` |
| Downstream is a shared Microsoft service | `[OPERATOR-FILL: Azure enterprise support contact]` |
| Unusual ADO write operations detected | `[OPERATOR-FILL: ADO admin + affected project owners]` |
| Financial data may have been accessed | `[OPERATOR-FILL: CFO + Audit committee per SOX]` |
