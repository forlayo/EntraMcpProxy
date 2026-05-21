using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Metrics;

/// <summary>
/// Integration tests for the Prometheus /metrics endpoint.
///
/// Verifies:
///   1. GET /metrics returns 200 with Prometheus text exposition format.
///   2. The content type identifies Prometheus format.
/// </summary>
public class MetricsEndpointTests
{
    [Fact]
    public async Task Metrics_endpoint_returns_200_with_prometheus_format()
    {
        // Arrange
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        // Act
        var resp = await client.GetAsync("/metrics");

        // Assert — endpoint exists and responds
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await resp.Content.ReadAsStringAsync();

        // Prometheus text format always starts with # HELP or # TYPE lines,
        // or at least contains the dotnet_ or process_ default metrics.
        body.Should().MatchRegex(@"(^|\n)#\s+(HELP|TYPE)\s+\w+");
    }

    [Fact]
    public async Task Metrics_endpoint_content_type_is_prometheus_text()
    {
        // Arrange
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        // Act
        var resp = await client.GetAsync("/metrics");

        // Assert — Content-Type contains the Prometheus exposition type
        resp.Content.Headers.ContentType?.MediaType
            .Should().Be("text/plain");
    }
}
