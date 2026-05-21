# EntraMcpProxy — Operations Runbook

## Deployment Checklist

### Pre-Deployment Gates

- [ ] All CI checks green (build, unit, integration, E2E, vulnerability scan, SBOM)
- [ ] Image pinned to a `@sha256:...` digest in the deployment manifest
- [ ] `DownstreamServers` allowlist reviewed
- [ ] `Proxy:EgressAllowlist` matches `DownstreamServers[*].BaseUrl` hosts
- [ ] `Proxy:AllowedRedirectUris` contains `https://claude.ai/api/mcp/auth_callback` and no other
- [ ] `Proxy:PublicBaseUrl` matches the ingress's external URL exactly
- [ ] `ASPNETCORE_ENVIRONMENT=Production` set
- [ ] `EntraId__RequireHttpsMetadata=true` (or unset — default is true)
- [ ] `EntraMcpProxy.Audit` log category piped to immutable sink
- [ ] Entra app registration:
  - [ ] `Ado.Mcp.Tools` granted as DELEGATED permission (not Application)
  - [ ] Redirect URI allowlist contains only `https://claude.ai/api/mcp/auth_callback`
  - [ ] "Allow public client flows" disabled
  - [ ] `user_impersonation` API scope exposed
  - [ ] `client_secret` rotated within last 90 days

### Change Control

Adding a new downstream MCP server to `DownstreamServers`:

1. Security review of the downstream MCP's tool catalog and permissions
2. Add the downstream's host to `Proxy:EgressAllowlist` in the same deployment
3. Set `Proxy:DownstreamServers:N:AllowedTools` to the approved tool list
4. Deploy and monitor `tool_set_changed` audit events for the first hour

Rotating the Entra `client_secret`:

1. Create a new secret in Entra app registration
2. Update Kubernetes secret / env var
3. Roll the deployment
4. Verify `/api/healthz` returns 200
5. Send a test `tools/call` via claude.ai
6. Once verified working, delete the old secret in Entra

### Incident Response

#### Suspected `client_secret` leak

1. **Immediate**: invalidate the secret in Entra app registration
   (revokes existing tokens within a few minutes — confirm in
   conditional access logs)
2. Generate a new secret
3. Update the deployment's secret reference
4. Roll the deployment
5. Audit the `EntraMcpProxy.Audit` log for the leak window — look
   for unusual `/token` request patterns

#### Suspected downstream MCP compromise

1. Disable the affected downstream in config (`Enabled: false`),
   redeploy
2. Audit `tool_invocation` events targeting the affected prefix
   from the suspected compromise window
3. Restore from a known-good downstream version
4. Re-enable with updated `AllowedTools` if the catalog changed

#### Proxy stops accepting auth

Symptoms: every `/mcp` returns 401, `/authorize` returns 5xx.

1. Check `/api/healthz` — if it's also failing, the issue is
   non-auth-related; check container logs and Kubernetes events
2. If health is fine but auth fails:
   - Verify Entra is reachable: `curl https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration` from the cluster
   - Verify the `client_secret` matches what's in Entra
   - Check Entra's "Sign-in logs" for failed authentication events

## Routine Operations

### Audit log review (weekly)

Look for:
- `authz_denied` events — investigate if more than baseline
- `pkce_missing` / `redirect_uri_rejected` events — possible probing
- `obo_exchange_failed` clusters — possible token revocation or client-secret issue
- `tool_set_changed` events — verify expected catalog changes
- `tool_invocation` events with `status: "exception"` over 5% of total — investigate the underlying downstream

### Capacity

Per-instance rate limit: `Proxy:RateLimit:RequestsPerMinute` (default 30). Total `/authorize` + `/token` traffic should sit well below the cap; if it doesn't, increase the cap or scale out.

### Updating dependencies

NuGet versions are pinned in `Directory.Packages.props`. Use `dotnet list package --vulnerable` regularly. CI fails on Critical or High vulnerabilities — investigate any new advisories within 24 hours.

The Docker base image is pinned by digest. To rotate:

```bash
docker pull mcr.microsoft.com/dotnet/aspnet:10.0
docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:10.0
# Update the @sha256:... in Dockerfile, repeat for the sdk image.
```

### Updating MCP SDK

The `ModelContextProtocol` packages are currently at `0.7.0-preview.1`. Production SHOULD migrate to a GA release when one is published. Track [the upstream releases](https://github.com/modelcontextprotocol/csharp-sdk/releases).

## References

- [Security findings list](../audit/2026-05-21-security-review.md)
- [Threat model](threat-model.md)
- [Remediation plan](superpowers/plans/2026-05-21-entra-mcp-proxy-remediation.md)
