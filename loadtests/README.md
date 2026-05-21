# EntraMcpProxy Load Tests

NBomber-based load test project. Operator-runs only — not part of CI.

Run these tests against a **deployed staging proxy** after completing the sandbox
validation runbook (`docs/sandbox-validation.md`).

---

## Prerequisites

- .NET 10 SDK
- A deployed staging instance of EntraMcpProxy with a known HTTPS URL
- (Optional but recommended) A real bearer token from a test user session, so the
  proxy's JWT validation succeeds during the test run

## Quick Start

```bash
# From the repository root
cd loadtests/EntraMcpProxy.LoadTests

# Run all three scenarios (2 min HappyPath + OBO storm + rate limit probe)
PROXY_BASE_URL=https://your-proxy.azurecontainerapps.io dotnet run

# Run a single scenario
PROXY_BASE_URL=https://your-proxy.azurecontainerapps.io SCENARIO=HappyPathLoad dotnet run
```

On Windows (PowerShell):

```powershell
$env:PROXY_BASE_URL = "https://your-proxy.azurecontainerapps.io"
$env:SCENARIO = "HappyPathLoad"
dotnet run
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROXY_BASE_URL` | Yes | — | HTTPS base URL of the deployed proxy. No trailing slash. |
| `SCENARIO` | No | `all` | One of `HappyPathLoad`, `OBOExchangeStorm`, `RateLimitProbing`, `all` |
| `LOAD_TEST_BEARER_TOKEN` | Recommended | — | A real Entra bearer token from a test user. When set, all scenarios use this token. Without it, self-signed tokens are used and the proxy returns 401 for every request. |
| `ENTRA_TENANT_ID` | No | `00000000-0000-0000-0000-000000000001` | Used for synthetic token minting (only relevant without `LOAD_TEST_BEARER_TOKEN`) |
| `ENTRA_CLIENT_ID` | No | `00000000-0000-0000-0000-000000000002` | Used for synthetic token audience (only relevant without `LOAD_TEST_BEARER_TOKEN`) |

## Obtaining a Real Bearer Token

The simplest approach for a test user:

```bash
# 1. Use the Azure CLI to get a token for the proxy's app registration
#    (replace CLIENT_ID and TENANT_ID with your proxy's values)
az login --tenant "$TENANT_ID"
TOKEN=$(az account get-access-token \
  --resource "api://$CLIENT_ID" \
  --query accessToken -o tsv)

# 2. Pass it to the load test
PROXY_BASE_URL=https://your-proxy.example.com \
LOAD_TEST_BEARER_TOKEN="$TOKEN" \
dotnet run
```

## Scenarios

### HappyPathLoad

- 50 concurrent virtual users
- 2-minute sustained load
- Each user sends `tools/list` JSON-RPC requests in a loop
- **Pass criteria**: P95 latency < 500ms, 5xx error rate < 1%

### OBOExchangeStorm

- 200 unique virtual users, each making exactly one `tools/call` request
- Forces 200 simultaneous OBO cache misses
- **Pass criteria**: zero 5xx errors (no server failures under OBO pressure)
- **After the run**: query your audit log for `obo_exchange` events and verify 200
  distinct `oid` values appear (confirms no token cross-contamination)

### RateLimitProbing

- 1 virtual user, 31 rapid-fire POST `/token` requests in 60 seconds
- **Pass criteria**: requests 1–30 return any non-429 status; at least 1 returns 429
- Verifies `Proxy:RateLimit:RequestsPerMinute=30` is enforced

## Build Only

```bash
dotnet build D:/workspace/EntraMcpProxy/loadtests/EntraMcpProxy.LoadTests/EntraMcpProxy.LoadTests.csproj
```

The load test project is NOT included in the main solution by design — it is a
standalone project so it does not affect `dotnet test` in CI.

## Reports

NBomber writes HTML and Markdown reports to a `reports/` directory created next to
the binary. Open `reports/report.html` in a browser after the run.

## Tuning

Scenario constants are defined at the top of each `Scenarios/*.cs` file:

- `HappyPathLoadScenario.ConcurrentUsers` (default 50)
- `HappyPathLoadScenario.Duration` (default 2 minutes)
- `OboExchangeStormScenario.UniqueUsers` (default 200)
- `RateLimitProbingScenario.ExpectedCap` (must match `Proxy:RateLimit:RequestsPerMinute`)

Recompile after changing any of these values.
