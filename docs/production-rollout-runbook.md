# EntraMcpProxy Production Rollout Runbook

> **Status:** Branch `security-remediation` is engineering-complete. This
> runbook covers what the OPERATOR must do to take this code to production.
> Each step has go/no-go criteria; do NOT skip ahead.
>
> Engineering artifacts:
> - `docs/sandbox-validation.md` — sandbox validation procedure
> - `docs/operations.md` — deployment checklist and change-control runbooks
> - `docs/threat-model.md` — trust boundaries, residual risks, assumptions
> - `docs/compliance/sox-controls.md` — SOX ITGC mapping (fill in before audit)
> - `docs/compliance/anthropic-vendor-risk-assessment.md` — vendor risk template
> - `docs/incident-runbooks/` — secret leak, auth outage, downstream compromise
> - `monitoring/` — Prometheus alert rules and Grafana dashboard JSON

---

## Timeline overview

```
Week 1:    Sandbox validation (3 days execution)
Week 1:    Third-party security review engagement starts (4 weeks calendar)
Week 1-2:  Production environment + observability + monitoring setup
Week 2:    Load testing + capacity planning (against staging)
Week 4-5:  Address third-party review findings
Week 5:    Penetration test scheduled
Week 5-6:  Internal pilot (5-10 users, 1 week)
Week 7-8:  Department beta (50-100 users, 2 weeks)
Week 9-10: General availability rollout

Total calendar:           ~10 weeks
Total engineering effort: ~3 person-weeks + $25-50k external
```

Phases 3 (infrastructure setup) and 2 (third-party review engagement) run in
parallel. Do not delay infrastructure work waiting for the security review.

---

## Phase 1: Sandbox validation (Week 1)

**Goal:** Empirically prove the proxy works against a real Entra tenant and a
real claude.ai session before any external investment. This is cheap and
deterministic — no surprises that block the third-party reviewer mid-engagement.

### Steps

- [ ] Set up a sandbox Azure tenant (separate from production — Global Admin or
      Application Admin access required)
- [ ] Set up a sandbox Azure DevOps organisation tied to the sandbox tenant
- [ ] Follow `docs/sandbox-validation.md` end to end, **in order**. Every
      command is spelled out; shell variables are declared at the top.
- [ ] Capture results for all 8 compatibility scenarios
- [ ] Capture results for all 6 security probe scenarios
- [ ] Attach captured artifacts (screenshots, log excerpts) to your issue
      tracker under a "Sandbox Validation" ticket

**Go/no-go:** ALL 8 compatibility scenarios PASS AND ALL 6 security probe
scenarios PASS. If any scenario fails:

1. File a bug on the `security-remediation` branch
2. Fix in code + re-run just that scenario before re-running the full suite
3. Do not engage the third-party reviewer until the full suite is green

---

## Phase 2: Third-party security review (Week 1 — engagement starts; 4 weeks calendar)

**Goal:** Independent verification of the security posture from a firm that
reviews OAuth and MCP proxy deployments routinely.

### Reviewer selection

Recommended firms (in no order): Trail of Bits, Latacora, NCC Group, Leviathan
Security, Bishop Fox. Scope: full repository + deployment manifests + a copy of
the completed `docs/threat-model.md`. Budget: $15-30k for a focused engagement.

### Steps

- [ ] Select reviewer and obtain quotes
- [ ] Contract signed; scope defined as:
  - Full repository (`security-remediation` branch at the tag `v0.2.0-prerelease`)
  - The deployment manifests and Kubernetes configs your team will use in production
  - Optional: dynamic testing against the sandbox deployment from Phase 1
- [ ] Share the following via a secure channel (encrypted file transfer or
      reviewer's client portal — never email):
  - Repository access (read-only fork or zip at the tagged commit)
  - `audit/2026-05-21-security-review.md` (the original audit + closure)
  - `docs/threat-model.md`
  - `docs/sandbox-validation.md` (so the reviewer can replicate Phase 1 if
    they want dynamic testing)
  - The load test results from Phase 4 (share when ready)
- [ ] Sandbox deployment URL shared with the reviewer for optional dynamic testing
- [ ] Final report received from reviewer
- [ ] Triage findings with engineering:
  - Critical / High: must be remediated before Phase 6 (internal pilot). Open
    a tracking ticket for each finding; close with a commit reference.
  - Medium: remediation plan documented; fix by Phase 7 (department beta) at
    the latest.
  - Low / Informational: logged and deferred to the post-GA backlog.
- [ ] Findings without a code-side fix (e.g., architectural constraints,
      Anthropic-side assumptions): documented as accepted residual risk in
      `docs/threat-model.md` with a rationale and owner sign-off.

**Go/no-go for Phase 6 (pilot):**
- Zero Critical / High findings open (either remediated in code, or formally
  accepted as residual risk with written approval from Security and Engineering
  leadership).
- Medium findings: remediation plan documented with target dates.

---

## Phase 3: Production infrastructure (parallel with Phase 2, Week 1-2)

**Goal:** Stand up the production cluster, ingress, secrets management,
observability stack, and log shipping before load testing.

This phase has no gate of its own; it feeds Phase 4 (load testing against
staging) and Phase 6 (pilot). Run it in parallel with Phase 2.

### Production cluster

- [ ] Provision Kubernetes cluster (AKS recommended for Entra integration)
- [ ] Configure ingress controller with TLS termination (cert-manager or
      ingress-nginx with Azure-managed certificate)
- [ ] Ingress CIDR restriction: proxy is not publicly routable on its HTTP port;
      only the ingress handles public traffic. Confirm with `kubectl get svc`.

### Secrets management

- [ ] Create Azure Key Vault (or equivalent) in the production subscription
- [ ] Store in Key Vault (never in deployment manifests or env files):
  - `EntraId--ClientSecret` (the Entra app registration secret)
  - `DownstreamServers--0--OBO--ClientSecret`
  - Any API keys for the downstream MCP server
- [ ] Configure Key Vault access policy for the AKS pod identity (Workload
      Identity or AAD Pod Identity)
- [ ] Add a Key Vault secret rotation reminder to your calendar (every 90 days)

### Container image

- [ ] Build and push the production image from the tagged commit:

  ```bash
  git checkout v0.2.0-prerelease
  IMAGE="yourregistry.azurecr.io/entra-mcp-proxy:v0.2.0-prerelease"
  docker build -t "$IMAGE" .
  docker push "$IMAGE"
  # Capture the digest
  docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE"
  ```

- [ ] Pin the deployment manifest to the `@sha256:...` digest (not the tag):

  ```yaml
  image: yourregistry.azurecr.io/entra-mcp-proxy@sha256:<digest>
  ```

- [ ] Verify the SBOM artefact from CI is attached to the image in the registry

### Environment configuration

Set these in Kubernetes `ConfigMap` (non-secret) and `Secret` (secrets):

```yaml
# ConfigMap
ASPNETCORE_ENVIRONMENT: "Production"
Proxy__PublicBaseUrl: "https://mcp.yourdomain.com"
Proxy__AllowedRedirectUris__0: "https://claude.ai/api/mcp/auth_callback"
Proxy__AllowedCorsOrigins__0: "https://claude.ai"
EntraId__Authority: "https://login.microsoftonline.com/{tenant-id}/v2.0"
EntraId__TenantId: "{tenant-id}"
EntraId__ClientId: "{client-id}"
EntraId__RequireHttpsMetadata: "true"
# [add DownstreamServers configuration per docs/operations.md]

# Secret (from Key Vault, never inline)
EntraId__ClientSecret: "<from Key Vault>"
DownstreamServers__0__OBO__ClientSecret: "<from Key Vault>"
```

Verify with `docs/operations.md` "Pre-Deployment Gates" checklist before
proceeding to load testing.

### Observability stack

- [ ] Deploy Prometheus + Grafana (or use Azure Monitor + Azure Managed Grafana)
- [ ] Import `monitoring/grafana-dashboard.json` into Grafana
- [ ] Apply `monitoring/prometheus-alerts.yml` to Prometheus Alertmanager
- [ ] Configure alert routing: Critical alerts → PagerDuty / on-call phone;
      Warning alerts → Slack `#platform-alerts`
- [ ] Verify `/metrics` endpoint is reachable from Prometheus scrape target
      (internal network only — NOT exposed externally):

  ```bash
  kubectl exec -n <namespace> deploy/entra-mcp-proxy -- \
    curl -s http://localhost:8080/metrics | grep ^entra_mcp
  ```

- [ ] Verify `/api/readyz` returns `{"status":"ready"}`:

  ```bash
  kubectl exec -n <namespace> deploy/entra-mcp-proxy -- \
    curl -s http://localhost:8080/api/readyz
  ```

### Log shipping

- [ ] Configure log shipping for the `EntraMcpProxy.Audit` logger category to
      an immutable sink (Azure Monitor with immutability lock, Splunk, or SIEM)
- [ ] Confirm audit events appear in the sink by triggering a test OAuth flow
      and querying for `event_type=oauth_token_issued`
- [ ] Confirm the sink's retention policy is at least 90 days (SOX requirement
      if applicable — see `docs/compliance/sox-controls.md`)

---

## Phase 4: Load + capacity testing (Week 2)

**Goal:** Confirm the proxy handles the expected concurrency without
performance degradation and that rate limits protect the OAuth endpoints.

Run this against a staging environment (production-like config, non-production
Entra app registration).

### Prerequisites

- Staging deployment running (same image as Phase 3 production candidate)
- NBomber load test project at `loadtests/EntraMcpProxy.LoadTests`
- .NET 9 SDK installed on the load driver machine

### Steps

- [ ] Run `HappyPathLoad` (simulates normal traffic — OAuth + tool calls):

  ```bash
  cd loadtests/EntraMcpProxy.LoadTests
  dotnet run --scenario HappyPathLoad \
    --target-url https://staging-mcp.yourdomain.com \
    --concurrency 50 \
    --duration-seconds 300
  ```

  **Go/no-go:** P95 latency < 500 ms at 50 concurrent users over 5 minutes.
  If P95 exceeds 500 ms, profile and fix before proceeding.

- [ ] Run `OBOExchangeStorm` (verifies per-user identity isolation under load):

  ```bash
  dotnet run --scenario OBOExchangeStorm \
    --target-url https://staging-mcp.yourdomain.com \
    --user-count 20 \
    --calls-per-user 50
  ```

  **Go/no-go:** Zero cross-user OID contamination in the downstream audit log.
  Any contamination is a CRITICAL regression — stop the rollout and file a bug.

- [ ] Run `RateLimitProbing` (confirms rate limits hold under burst):

  ```bash
  dotnet run --scenario RateLimitProbing \
    --target-url https://staging-mcp.yourdomain.com
  ```

  **Go/no-go:** HTTP 429 responses appear at the expected rate; zero 5xx
  responses during the rate-limit burst.

- [ ] Capture and archive all load test reports (HTML + JSON in NBomber output
      directory). Share with the third-party reviewer if they request them.

- [ ] Review Prometheus/Grafana during the load run:
  - `entra_mcp_obo_cache_hit_ratio` should stabilise above 0.7 at steady state
  - `entra_mcp_downstream_errors_total` should be zero
  - Circuit-breaker metrics should show CLOSED state throughout

- [ ] Capacity plan: from the load test results, determine your expected peak
      concurrency, multiply by 1.5× safety margin, and confirm the pod
      resource requests/limits in the deployment manifest match.

---

## Phase 5: Penetration test (Week 5)

**Goal:** Adversarial validation of the deployed proxy against the attack
vectors in `docs/threat-model.md`.

### Engagement scope

Agree with the pen test firm (can be the same firm as Phase 2 or different):

- Full black-box test of the public OAuth endpoints (`/authorize`, `/token`,
  `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`)
- Authenticated test of the MCP endpoints (using a test Entra identity)
- Test of the security probe scenarios from `docs/sandbox-validation.md` Part 2
- Dynamic testing of the `X-Forwarded-Host` spoofing surface (threat-model trust
  boundary 1)
- Cross-user token isolation: two test accounts, concurrent tool calls, verify no
  OBO token crossing

### Steps

- [ ] Schedule pen test for the end of Week 5 (after Phase 2 findings are remediated)
- [ ] Provide the pen test team with:
  - Two test Entra identities in the staging tenant
  - The threat model (`docs/threat-model.md`)
  - The list of known residual risks (accepted from Phase 2)
  - Grafana read-only access to staging observability
- [ ] During the test: monitor Prometheus for anomalies; confirm the audit log
      captures all test events
- [ ] Receive findings report; triage with engineering:
  - Critical / High: block Phase 6; fix and re-test the specific finding before pilot
  - Medium / Low: document and plan for Phase 8 (GA) or post-GA

**Go/no-go for Phase 6:** Zero Critical / High pen test findings open.

---

## Phase 6: Internal pilot (Week 5-6)

**Goal:** Real-world validation with 5-10 users from your own engineering or
ops team who understand that this is a pilot and will report issues actively.

### Enrollment

- [ ] Identify 5-10 pilot users (engineers and/or ops staff — not end-users)
- [ ] Brief them: what the proxy does, how to raise issues (Slack channel +
      issue tracker), that this is a pilot and behaviour may change
- [ ] Add each user's Entra OID to the pilot group (if you have added
      per-tool or per-group authorization via `Proxy:DownstreamServers:N:AllowedTools`)
- [ ] Deploy to production using the staging image (same `@sha256:...` digest
      validated in Phase 4)
- [ ] Send connection instructions: MCP connector URL is
      `https://mcp.yourdomain.com/mcp`; follow `docs/sandbox-validation.md`
      Part 1 steps 8.x for the claude.ai connector setup

### Observation criteria (1 week)

Monitor for:

- [ ] Zero P0/P1 incidents in the first 48 hours (go back to Phase 4 if any)
- [ ] `entra_mcp_obo_exchange_errors_total` stays at zero under normal use
- [ ] `entra_mcp_tool_calls_total` count matches expected pilot volume
- [ ] No unexpected `circuit_breaker_state` transitions to OPEN
- [ ] No cross-user complaints ("I'm seeing someone else's data")
- [ ] All pilot users can authenticate and use at least one tool successfully

### Exit criteria

- [ ] 1 week operated without a P0/P1
- [ ] Pilot user feedback collected (short survey or Slack retrospective)
- [ ] No unresolved open issues blocking Phase 7

**Go/no-go for Phase 7:** All exit criteria met. If a P0/P1 occurred and was
fixed mid-pilot, reset the 1-week clock from the fix.

---

## Phase 7: Department beta (Week 7-8)

**Goal:** Scaled validation with 50-100 users from the target department
(likely DevOps / engineering) for 2 weeks.

### Enrollment

- [ ] Communicate to the department: what the proxy does, how to raise issues,
      that this is a beta (occasional downtime possible with notice)
- [ ] Add the department's Entra group to the authorization configuration if
      using per-group access controls
- [ ] Update your capacity plan based on observed pilot load; adjust pod
      replicas if needed (add a Horizontal Pod Autoscaler if you have not
      already)

### Monitoring thresholds (2 weeks)

Set alert thresholds tighter than production defaults for the beta period:

- `entra_mcp_obo_exchange_errors_total` > 0 → page on-call immediately
- P95 tool-call latency > 1 second over a 5-minute window → alert
- Any `circuit_breaker_state` → OPEN → alert within 2 minutes

### Support flow

- Establish a Slack channel (e.g., `#mcp-beta-support`) for users to raise
  issues directly
- Commit to a 4-hour SLA for P0/P1 during business hours
- Triage all issues within 24 hours

### Exit criteria

- [ ] 2 weeks operated with no P0/P1 (or all P0/P1s resolved and clocks reset)
- [ ] `entra_mcp_obo_exchange_errors_total` remains zero throughout
- [ ] P95 latency < 500 ms throughout (Grafana `tool_call_duration_p95` panel)
- [ ] Remaining Phase 2 Medium findings remediated (or formally deferred with
      written approval)
- [ ] `docs/compliance/sox-controls.md` operator fields filled in (if SOX applies)
- [ ] `docs/compliance/anthropic-vendor-risk-assessment.md` completed and
      submitted to your vendor risk team

**Go/no-go for Phase 8:** All exit criteria met.

---

## Phase 8: General availability (Week 9-10)

**Goal:** Full enrollment of all intended users with sustained monitoring.

### Rollout sequence

- [ ] Communicate GA date to all stakeholders (at least 5 business days notice)
- [ ] Remove any pilot/beta enrollment restrictions (open the Entra group or
      remove per-group allow lists if you were using them as a gate)
- [ ] Scale pod replicas to handle the full expected user count at 1.5×
      headroom (refer to capacity plan from Phase 4)
- [ ] Confirm Horizontal Pod Autoscaler is configured with appropriate min/max
      bounds

### Post-launch (first week)

- [ ] Monitor Grafana continuously for the first 48 hours
- [ ] On-call rotation is active (no nights/weekends gaps)
- [ ] `EntraMcpProxy.Audit` events flowing to the immutable sink confirmed
  - Spot-check: query for the last 24 hours of `oauth_token_issued` events
    and confirm user count matches enrolment
- [ ] No increase in `entra_mcp_obo_exchange_errors_total` or
      `entra_mcp_downstream_errors_total` compared to beta baseline
- [ ] Document the GA milestone in your incident tracker

### Post-launch retrospective (end of Week 10)

- [ ] Team retrospective covering: what went well, what had to be fixed, what
      to carry into the next rollout
- [ ] Update `docs/threat-model.md` with any new trust assumptions discovered
      in production
- [ ] Schedule the first quarterly secret rotation (90 days from GA date)
- [ ] Schedule a 6-month post-GA review to revisit the deferred items:
  - L18 magic strings refactor
  - N15 `jti` replay tracking (evaluate whether the threat model warrants it)
  - Any Medium findings formally deferred during Phase 2

---

## Rollback procedures

### Any phase: configuration-only rollback

If the issue is a misconfigured environment variable or secret:

1. Identify the bad value from the audit log or pod logs (`kubectl logs`)
2. Update the `ConfigMap` or `Secret`:
   ```bash
   kubectl edit configmap entra-mcp-proxy-config -n <namespace>
   # or
   kubectl edit secret entra-mcp-proxy-secrets -n <namespace>
   ```
3. Roll the deployment:
   ```bash
   kubectl rollout restart deployment/entra-mcp-proxy -n <namespace>
   ```
4. Confirm `/api/readyz` returns `{"status":"ready"}` after the restart
5. Watch logs for errors: `kubectl logs -f deploy/entra-mcp-proxy -n <namespace>`

### Any phase: image rollback

If the issue is in the application code:

1. Identify the previous good image digest from your deployment history or
   the CI registry
2. Update the deployment manifest:
   ```bash
   kubectl set image deployment/entra-mcp-proxy \
     entra-mcp-proxy=yourregistry.azurecr.io/entra-mcp-proxy@sha256:<previous-digest> \
     -n <namespace>
   ```
3. Confirm the rollout:
   ```bash
   kubectl rollout status deployment/entra-mcp-proxy -n <namespace>
   ```
4. Verify `/api/readyz` and audit log events
5. File a post-mortem within 24 hours

### Phase 6-8: secret rotation after suspected compromise

Follow `docs/incident-runbooks/runbook-secret-leak.md` exactly. Do not
improvise. Time to containment target is 30 minutes from detection.

### Phase 6-8: downstream MCP compromise or misbehaviour

Follow `docs/incident-runbooks/runbook-downstream-compromise.md`. The key
immediate action is to remove the downstream from `Proxy:DownstreamServers`
and deploy — this removes its tools from Claude's view without any downtime
for other downstreams.

---

## Sign-off

All four sign-offs must be obtained before Phase 8 (GA). They may be obtained
incrementally (e.g., Engineering and Security sign off after Phase 5, Compliance
and Operations sign off before Phase 8).

- [ ] **Security team sign-off** — confirms Phase 2 (third-party review) and
      Phase 5 (pen test) findings are resolved or formally accepted
- [ ] **Compliance / Privacy team sign-off** — confirms `docs/compliance/sox-controls.md`
      and `docs/compliance/anthropic-vendor-risk-assessment.md` are completed
      and approved; confirms data residency and retention requirements are met
- [ ] **Engineering leadership sign-off** — confirms the production readiness
      gate (`audit/2026-05-21-security-review.md` closure section) and all
      Phase 1-5 exit criteria are met
- [ ] **Operations sign-off** — confirms the monitoring stack is operational,
      on-call rotation is in place, and incident runbooks have been rehearsed
      (tabletop exercise recommended)
- [ ] **Vendor risk approval (Anthropic)** — the `client_secret` is held by
      Anthropic's infrastructure. Confirm your organisation's vendor risk
      process has approved Anthropic as a data processor for the identities
      that will use this connector. Use the template in
      `docs/compliance/anthropic-vendor-risk-assessment.md`.
