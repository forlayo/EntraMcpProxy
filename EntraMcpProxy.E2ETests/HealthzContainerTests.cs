using System.Net;
using System.Threading.Tasks;
using EntraMcpProxy.E2ETests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.E2ETests;

[Collection("E2E")]
public class HealthzContainerTests
{
    private readonly ProxyContainerFixture _fx;

    public HealthzContainerTests(ProxyContainerFixture fx)
    {
        _fx = fx;
    }

    [Fact]
    public async Task Healthz_via_container_returns_200()
    {
        var resp = await _fx.Http.GetAsync("/api/healthz");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
