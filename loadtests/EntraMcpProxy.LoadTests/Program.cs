using EntraMcpProxy.LoadTests;
using EntraMcpProxy.LoadTests.Scenarios;
using NBomber.CSharp;

// ---------------------------------------------------------------------------
// EntraMcpProxy Load Test Runner
//
// Usage (see loadtests/README.md for full details):
//
//   # Run all scenarios against a deployed proxy:
//   PROXY_BASE_URL=https://your-proxy.example.com dotnet run
//
//   # Run a single scenario:
//   PROXY_BASE_URL=https://your-proxy.example.com SCENARIO=HappyPathLoad dotnet run
//
// Required environment variables:
//   PROXY_BASE_URL   — HTTPS base URL of the deployed proxy (no trailing slash)
//
// Optional environment variables:
//   SCENARIO              — one of: HappyPathLoad, OBOExchangeStorm, RateLimitProbing
//                           If omitted, all scenarios run sequentially.
//   ENTRA_TENANT_ID       — tenant ID for synthetic token minting (default: test-tenant)
//   ENTRA_CLIENT_ID       — client ID for synthetic token audience (default: test-client)
//   LOAD_TEST_BEARER_TOKEN — a real bearer token from a test user session; when set,
//                            all scenarios use this token instead of self-signed tokens.
//
// IMPORTANT: The proxy validates JWTs against the real Entra JWKS. Self-signed
// tokens are rejected by a production proxy (401). To get meaningful throughput
// and latency numbers from HappyPathLoad, supply a real token via
// LOAD_TEST_BEARER_TOKEN, or deploy the proxy with a fake Entra authority.
// ---------------------------------------------------------------------------

string proxyBaseUrl = Environment.GetEnvironmentVariable("PROXY_BASE_URL")
    ?? throw new InvalidOperationException(
        "PROXY_BASE_URL environment variable is required.\n" +
        "Example: PROXY_BASE_URL=https://your-proxy.example.com dotnet run");

string scenario = Environment.GetEnvironmentVariable("SCENARIO") ?? "all";
string tenantId = Environment.GetEnvironmentVariable("ENTRA_TENANT_ID")
    ?? "00000000-0000-0000-0000-000000000001";
string clientId = Environment.GetEnvironmentVariable("ENTRA_CLIENT_ID")
    ?? "00000000-0000-0000-0000-000000000002";

Console.WriteLine($"Target:   {proxyBaseUrl}");
Console.WriteLine($"Scenario: {scenario}");
Console.WriteLine();

using var loadTestConfig = new LoadTestConfig(proxyBaseUrl, tenantId, clientId);

var scenarios = scenario switch
{
    "HappyPathLoad"     => [HappyPathLoadScenario.Build(loadTestConfig)],
    "OBOExchangeStorm"  => [OboExchangeStormScenario.Build(loadTestConfig)],
    "RateLimitProbing"  => [RateLimitProbingScenario.Build(loadTestConfig)],
    "all" => new[]
    {
        HappyPathLoadScenario.Build(loadTestConfig),
        OboExchangeStormScenario.Build(loadTestConfig),
        RateLimitProbingScenario.Build(loadTestConfig),
    },
    _ => throw new ArgumentException(
        $"Unknown scenario '{scenario}'. " +
        "Valid values: HappyPathLoad, OBOExchangeStorm, RateLimitProbing, all"),
};

NBomberRunner
    .RegisterScenarios(scenarios)
    .Run();
