using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests;

public class HealthzSmokeTests
{
    [Fact]
    public async Task Healthz_returns_200()
    {
        await using var factory = new ProxyAppFactory();
        using HttpClient client = factory.CreateClient();
        HttpResponseMessage resp = await client.GetAsync("/api/healthz");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    /// <summary>
    /// Block B: /api/readyz exists and responds (200 or 503) — the important
    /// assertion is that the endpoint is registered and returns a valid
    /// health-check response, not a 404.
    ///
    /// In the integration test environment, EntraConnectivityHealthCheck will
    /// fail (FakeEntra is not started for this factory), so we expect either
    /// 200 (all healthy) or 503 (degraded/unhealthy). Both are valid — what
    /// matters is that the endpoint exists.
    /// </summary>
    [Fact]
    public async Task Readyz_endpoint_exists_and_returns_valid_health_check_response()
    {
        await using var factory = new ProxyAppFactory();
        using HttpClient client = factory.CreateClient();
        HttpResponseMessage resp = await client.GetAsync("/api/readyz");

        // Should not be 404 — the endpoint must be registered
        resp.StatusCode.Should().NotBe(HttpStatusCode.NotFound,
            "readyz must be registered as a health check endpoint");

        // Must be a health-check response (200 = all healthy, 503 = degraded/unhealthy)
        var validCodes = new[] { HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable };
        validCodes.Should().Contain(resp.StatusCode,
            "readyz must return 200 or 503 depending on upstream reachability");
    }
}
