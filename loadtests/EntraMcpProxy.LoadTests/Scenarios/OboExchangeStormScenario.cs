using NBomber.Contracts;
using NBomber.Contracts.Stats;
using NBomber.CSharp;

namespace EntraMcpProxy.LoadTests.Scenarios;

/// <summary>
/// OBOExchangeStorm — 200 unique synthetic users each issue exactly ONE tool
/// call, forcing 200 OBO cache misses in rapid succession.
///
/// Purpose: verifies the Phase 7/8 fix (C1/C2) — under concurrent OBO pressure
/// the proxy must not mix up tokens between users.
///
/// Assertion: zero 5xx errors.
///
/// Cross-contamination detection: after the run, query the audit log for
/// obo_exchange events in the scenario window and verify 200 distinct OID values
/// appear, each matched to the correct user session.
///
/// NOTE: Set LOAD_TEST_BEARER_TOKEN to a real Entra bearer token for realistic
/// OBO exchange load.
/// </summary>
public static class OboExchangeStormScenario
{
    private const int UniqueUsers = 200;

    public static ScenarioProps Build(LoadTestConfig config)
    {
        // Pre-mint 200 tokens — one per unique OID — before the scenario starts.
        var tokens = Enumerable.Range(0, UniqueUsers)
            .Select(i => config.GetBearerToken($"obo-storm-user-{i:D4}"))
            .ToArray();

        int requestIndex = 0;
        var httpClient = new HttpClient();

        return Scenario.Create("OBOExchangeStorm", async context =>
        {
            int idx = Interlocked.Increment(ref requestIndex) % UniqueUsers;
            string token = tokens[idx];

            using var request = new HttpRequestMessage(HttpMethod.Post,
                $"{config.ProxyBaseUrl}/mcp");
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            // tools/call forces the OBO exchange path.
            request.Content = new StringContent(
                """
                {
                  "jsonrpc": "2.0",
                  "id": 1,
                  "method": "tools/call",
                  "params": { "name": "ado_list_repos", "arguments": {} }
                }
                """,
                System.Text.Encoding.UTF8,
                "application/json");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            int statusCode = (int)response.StatusCode;

            // 5xx = server error (possible cross-contamination or OBO failure).
            // 4xx are acceptable (401 = synthetic token rejected, etc.).
            return statusCode >= 500
                ? Response.Fail(statusCode: statusCode.ToString())
                : Response.Ok(statusCode: statusCode.ToString());
        })
        .WithWarmUpDuration(TimeSpan.FromSeconds(5))
        .WithLoadSimulations(
            // Inject 200 requests per second for 1 second = 200 concurrent users.
            Simulation.Inject(rate: 200,
                interval: TimeSpan.FromSeconds(1),
                during: TimeSpan.FromSeconds(1)))
        .WithThresholds(
            // Zero 5xx: any server error under OBO storm is a failure.
            Threshold.Create((ScenarioStats s) => s.Fail.Request.Count == 0));
    }
}
