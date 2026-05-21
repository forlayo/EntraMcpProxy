# EntraMcpProxy — Production Readiness Checklist

Fork this file into your project tracker. Every item must be checked before
promoting to production. Items are grouped by category. Where a prior doc is
referenced, the link is relative to the repo root.

---

## 1 — Code Quality Gates

- [ ] All unit tests pass (`dotnet test EntraMcpProxy.Tests`)
- [ ] All integration tests pass (`dotnet test EntraMcpProxy.IntegrationTests`)
- [ ] All E2E tests pass (`dotnet test EntraMcpProxy.E2ETests`)
- [ ] Zero compiler warnings (`TreatWarningsAsErrors` is enabled in `Directory.Build.props`)
- [ ] `dotnet list package --vulnerable` returns no High or Critical advisories
- [ ] SBOM generated (`dotnet CycloneDX` or equivalent) and archived
- [ ] Static analysis / SAST tool run (e.g., Semgrep, CodeQL); zero high-severity findings
- [ ] Code review approved by a second engineer (PR review documented)
- [ ] Branch protection rules enforce at least one required reviewer on `main`

---

## 2 — Build & Supply Chain

- [ ] Docker base image pinned to a `@sha256:...` digest in `Dockerfile`
- [ ] SDK image also pinned by digest (the `FROM ... AS build` stage)
- [ ] NuGet packages version-pinned in `Directory.Packages.props`
- [ ] `packages.lock.json` committed and `RestoreLockedMode=true` in CI
- [ ] Container image built and signed in CI (GitHub Actions workflow in `.github/workflows/`)
- [ ] Image pushed to a private registry (not public Docker Hub unless intentional)
- [ ] Image digest recorded in the deployment manifest

---

## 3 — Entra App Registration

- [ ] App registration created in the correct (production) tenant — not in sandbox
- [ ] Display name documents the purpose (e.g., `EntraMcpProxy-Production`)
- [ ] `identifierUri` set to `api://<CLIENT_ID>`
- [ ] Redirect URI allowlist contains ONLY `https://claude.ai/api/mcp/auth_callback`
- [ ] No additional redirect URIs present (verify via `az ad app show`)
- [ ] "Allow public client flows" (`isFallbackPublicClient`) is `false`
- [ ] `user_impersonation` scope exposed on the app's API
- [ ] Azure DevOps `user_impersonation` delegated permission granted
- [ ] Admin consent granted for the delegated permission
- [ ] `client_secret` created with a maximum lifetime ≤ 90 days
- [ ] `client_secret` expiry date recorded in a secrets rotation tracker
- [ ] `client_secret` stored in a secret store (Key Vault, Kubernetes Secret) — NOT in `appsettings.json`
- [ ] Conditional access policy applied to the app (if org policy requires MFA)

---

## 4 — Proxy Configuration

- [ ] `ASPNETCORE_ENVIRONMENT=Production` set in the container environment
- [ ] `EntraId__RequireHttpsMetadata=true` (or unset — default is `true`)
- [ ] `Proxy__PublicBaseUrl` matches the ingress's external HTTPS URL exactly (no trailing slash)
- [ ] `Proxy__AllowedRedirectUris__0=https://claude.ai/api/mcp/auth_callback` and no others
- [ ] `Proxy__EgressAllowlist` contains only the downstream MCP hostname(s) — no wildcards
- [ ] `Proxy__DownstreamServers` entries reviewed: `Name`, `BaseUrl`, `OBO__Scope`, `AllowedTools`
- [ ] `Proxy__RateLimit__RequestsPerMinute` set (default 30; tune based on expected traffic)
- [ ] `Proxy__ToolResult__MaxBytes` set (default 262144 = 256 KB)
- [ ] `Proxy__RefreshIntervalMinutes` set appropriately (default 5)
- [ ] Dev-only placeholders in `appsettings.json` replaced with env-var references
- [ ] Startup validator runs clean (proxy logs no config validation errors on first boot)

---

## 5 — Per-Environment Configuration Verification

### Development

- [ ] `ASPNETCORE_ENVIRONMENT=Development` set
- [ ] `EntraId__RequireHttpsMetadata=false` acceptable for local dev
- [ ] Downstream servers point at dev/staging ADO org, not production

### Staging

- [ ] Separate Entra app registration (do NOT share `client_secret` with production)
- [ ] Separate `PublicBaseUrl` pointing at staging ingress
- [ ] Separate `EgressAllowlist` for staging downstream servers
- [ ] Sandbox validation runbook (`docs/sandbox-validation.md`) executed against staging
- [ ] All 8 compatibility scenarios: PASS
- [ ] All 6 security probes: PASS

### Production

- [ ] All items in sections 3–4 above verified against production config
- [ ] Production Entra app registration separate from staging
- [ ] `client_secret` different from staging
- [ ] Ingress TLS certificate valid and not expiring within 30 days
- [ ] Ingress enforces minimum TLS 1.2

---

## 6 — Network / Ingress

- [ ] Proxy is reachable only via HTTPS (port 443) externally
- [ ] HTTP (port 80) either redirects to HTTPS or is closed
- [ ] Kestrel not exposed directly to the internet (ingress terminates TLS)
- [ ] `X-Forwarded-For` / `X-Forwarded-Host` NOT trusted by the proxy (UseForwardedHeaders removed — finding H5)
- [ ] Ingress IP allowlist configured if the set of callers is known (Anthropic ASNs)
- [ ] DDoS protection enabled on the ingress (Azure DDoS Standard, Cloudflare, etc.)
- [ ] Egress from the proxy container is restricted to `Proxy__EgressAllowlist` hosts
- [ ] No outbound internet access except to Entra (`login.microsoftonline.com`) and the configured downstream MCP hosts

---

## 7 — Secrets Management

- [ ] `client_secret` injected via secret store — NOT environment variable literal in deployment manifest
- [ ] Secret store access is role-restricted (only the proxy's managed identity can read the secret)
- [ ] Secret rotation procedure documented (`docs/operations.md` — "Rotating the Entra client_secret")
- [ ] Secret rotation tested in staging (old secret deleted, new one working)
- [ ] Secrets rotation frequency entered into a calendar reminder (every 90 days or per org policy)
- [ ] No secrets committed to the repository (`git log -p | grep -i secret` returns nothing alarming)

---

## 8 — Observability

### Metrics

- [ ] Prometheus `/metrics` endpoint accessible to the scraper (not to the public internet)
- [ ] `oauth_rejections_total` metric scraping confirmed (Block B)
- [ ] `obo_exchanges_total` metric scraping confirmed
- [ ] `tool_latency_seconds` histogram scraping confirmed
- [ ] `entra_mcp_proxy_obo_cache_entries` gauge scraping confirmed
- [ ] Grafana dashboard imported (`monitoring/grafana-dashboard.json`)
- [ ] Dashboard shows live data (not "No data")

### Tracing

- [ ] OpenTelemetry exporter endpoint configured (`OTEL_EXPORTER_OTLP_ENDPOINT`)
- [ ] Traces arriving in the trace backend (Jaeger, Tempo, Azure Monitor)
- [ ] Trace sampling rate set appropriately (100% in staging, ~10% in production unless debugging)

### Audit Logging

- [ ] `EntraMcpProxy.Audit` log category piped to an immutable sink
- [ ] Sink wiring verified (`docs/audit-sink-wiring.md` options 1, 2, or 3)
- [ ] Audit events visible in the sink after a test tool call
- [ ] Retention period set to ≥ 90 days (or per compliance requirement)
- [ ] Immutability / WORM storage enabled on the sink (Azure Monitor immutability, S3 Object Lock, etc.)

### Health

- [ ] `/api/healthz` returns HTTP 200 and is scraped by the ingress health probe
- [ ] Unhealthy state triggers at least one replica restart (liveness probe configured)
- [ ] Readiness probe configured so the proxy is only sent traffic after startup completes

---

## 9 — Alerting

- [ ] Prometheus alert rules loaded (`monitoring/prometheus-alerts.yml`)
- [ ] Alertmanager configured to route alerts to on-call channel (Slack, PagerDuty, etc.)
- [ ] Alert: `EntraMcpProxyDown` fires within 2 minutes of container going unhealthy
- [ ] Alert: `HighOauthRedirectUriRejections` fires after >10 bad redirect URIs in 1 minute
- [ ] Alert: `HighOauthPkceMissingRate` fires after >10 PKCE-missing requests in 1 minute
- [ ] Alert: `HighOboExchangeErrorRate` fires when OBO error ratio >5% over 10 minutes
- [ ] Alert: `HighToolLatencyP99` fires when P99 latency exceeds 5 seconds
- [ ] Alert: `OboCacheGrowingUnbounded` fires when cache entries exceed 10000
- [ ] All alert rules verified to fire correctly in staging (fire + resolve cycle tested)

---

## 10 — Monitoring & Incident Runbooks

- [ ] Incident runbooks available to all on-call engineers:
  - [ ] `docs/incident-runbooks/runbook-secret-leak.md`
  - [ ] `docs/incident-runbooks/runbook-downstream-compromise.md`
  - [ ] `docs/incident-runbooks/runbook-auth-outage.md`
- [ ] Incident runbook drill completed (tabletop or live-fire in staging)
- [ ] On-call rotation defined; at least 2 engineers have access to the deployment
- [ ] Escalation path documented (who to call if the proxy is down and the on-call can't fix it)
- [ ] Runbooks linked from the internal wiki or on-call handbook

---

## 11 — Change Management

- [ ] All changes to `DownstreamServers` go through a security review checklist (`docs/operations.md`)
- [ ] `AllowedTools` for each downstream server is explicitly set (no wildcard / permit-all in production)
- [ ] Deployment is reproducible: same image digest + same config = same behaviour
- [ ] Rollback procedure documented and tested (previous image digest, one-command redeploy)
- [ ] Change log / release notes maintained for each deployment

---

## 12 — Vendor Risk Assessment

- [ ] Anthropic vendor risk assessment completed (`docs/compliance/anthropic-vendor-risk-assessment.md`)
- [ ] Risk acceptance signed by the appropriate stakeholder (CISO or equivalent)
- [ ] Questions listed in the vendor assessment sent to Anthropic and responses received (or risk-accepted without response per org policy)
- [ ] Azure DevOps Remote MCP vendor assessment completed (separate document if required)

---

## 13 — Privacy Review

- [ ] Data flows documented: what user data transits the proxy? (identity claims, tool args, tool results)
- [ ] Data classification confirmed (see `docs/compliance/sox-controls.md` §5)
- [ ] PII handling reviewed: tool results may contain user-owned data — confirm no logging of raw results
- [ ] Audit log retention period reviewed against data-minimisation requirements
- [ ] GDPR / CCPA / applicable privacy regulation review completed (or waived with written justification)
- [ ] Data Processing Agreement with Anthropic reviewed (Anthropic processes auth flows on claude.ai)

---

## 14 — SOX Controls

- [ ] SOX control mapping document completed (`docs/compliance/sox-controls.md`)
- [ ] All `[OPERATOR-FILL]` markers in the SOX template replaced with org-specific controls
- [ ] Access controls section reviewed by IT audit
- [ ] Change management section reviewed by IT audit
- [ ] Audit logging section confirmed as immutable (see section 8 above)
- [ ] Segregation of duties section reviewed: deployer ≠ audit log reviewer ≠ Entra app owner (or compensating control documented)
- [ ] SOX controls signed off by the control owner

---

## 15 — Rollout

- [ ] Staging deployment running for ≥ 48 hours without critical alerts
- [ ] Load test executed (`loadtests/README.md`) — all assertions pass:
  - [ ] HappyPathLoad: P95 < 500ms, error rate < 1%
  - [ ] OBOExchangeStorm: no errors, no cross-contamination
  - [ ] RateLimitProbing: 30 succeed, 31st returns 429
- [ ] Production deployment approved by change advisory board (or equivalent)
- [ ] Go-live communication sent to affected users
- [ ] Post-go-live monitoring window defined (watch alerts for ≥ 2 hours after deploy)
- [ ] Hypercare period defined (increased on-call coverage for first 72 hours)
