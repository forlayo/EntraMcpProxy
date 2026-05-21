using System.Net;
using System.Threading.Tasks;
using EntraMcpProxy.E2ETests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.E2ETests;

[Collection("E2E")]
public class HealthzContainerTests
{
    [Fact]
    public async Task Healthz_via_container_returns_200()
    {
        await using var fx = await ProxyContainerFixture.StartAsync();
        var resp = await fx.Http.GetAsync("/api/healthz");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
