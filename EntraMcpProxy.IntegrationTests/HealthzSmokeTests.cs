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
}
