using NBomber.Contracts;
using NBomber.Contracts.Stats;
using NBomber.CSharp;

namespace EntraMcpProxy.LoadTests.Scenarios;

/// <summary>
/// HappyPathLoad — 50 concurrent synthetic users each making repeated tool list
/// requests for 2 minutes.
///
/// Assertions:
///   - P95 latency &lt; 500ms  (threshold: scenarioStats.Ok.Latency.Percent95 &lt; 500)
///   - Error rate (5xx responses) &lt; 1%
///
/// Each virtual user calls /mcp with a tools/list JSON-RPC request, simulating
/// the steady-state load of claude.ai polling for available tools.
///
/// NOTE: Set LOAD_TEST_BEARER_TOKEN to a real Entra bearer token so the proxy
/// accepts the requests and OBO exchange latency is included in the measurement.
/// Without it, self-signed tokens are used and the proxy returns 401.
/// </summary>
public static class HappyPathLoadScenario
{
    private const int ConcurrentUsers = 50;
    private static readonly TimeSpan Duration = TimeSpan.FromMinutes(2);

    public static ScenarioProps Build(LoadTestConfig config)
    {
        var httpClient = new HttpClient();

        return Scenario.Create("HappyPathLoad", async context =>
        {
            // Unique OID per virtual user keeps OBO cache pressure realistic.
            string oid = $"load-test-user-{context.ScenarioInfo.InstanceNumber:D4}";
            string token = config.GetBearerToken(oid);

            using var request = new HttpRequestMessage(HttpMethod.Post,
                $"{config.ProxyBaseUrl}/mcp");
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Content = new StringContent(
                """{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""",
                System.Text.Encoding.UTF8,
                "application/json");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            int statusCode = (int)response.StatusCode;

            // 5xx = server error → fail. 2xx / 4xx (incl. 401) → ok.
            return statusCode >= 500
                ? Response.Fail(statusCode: statusCode.ToString())
                : Response.Ok(statusCode: statusCode.ToString());
        })
        .WithWarmUpDuration(TimeSpan.FromSeconds(10))
        .WithLoadSimulations(
            Simulation.KeepConstant(copies: ConcurrentUsers, during: Duration))
        .WithThresholds(
            // P95 latency < 500ms
            Threshold.Create((ScenarioStats s) => s.Ok.Latency.Percent95 < 500),
            // 5xx error rate < 1%
            Threshold.Create((ScenarioStats s) => s.Fail.Request.Percent < 1.0));
    }
}
