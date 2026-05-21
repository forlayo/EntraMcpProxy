using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class EntraConnectivityHealthCheckTests
{
    private static IOptions<EntraIdOptions> MakeOptions(string authority = "https://login.example.com/tenantId/v2.0")
    {
        var opts = new EntraIdOptions
        {
            Authority = authority,
            ClientId = "00000000-0000-0000-0000-000000000001",
            TenantId = "00000000-0000-0000-0000-000000000002",
        };
        return Options.Create(opts);
    }

    private static HealthCheckContext MakeContext() =>
        new() { Registration = new HealthCheckRegistration("test", _ => throw new InvalidOperationException(), null, null) };

    [Fact]
    public async Task Returns_Healthy_when_discovery_endpoint_returns_200()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var handler = new FakeHttpMessageHandler(HttpStatusCode.OK);
        factory.CreateClient("entra-token-relay").Returns(new HttpClient(handler));

        var check = new EntraConnectivityHealthCheck(factory, MakeOptions());

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("200");
    }

    [Fact]
    public async Task Returns_Degraded_when_discovery_endpoint_returns_5xx()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var handler = new FakeHttpMessageHandler(HttpStatusCode.ServiceUnavailable);
        factory.CreateClient("entra-token-relay").Returns(new HttpClient(handler));

        var check = new EntraConnectivityHealthCheck(factory, MakeOptions());

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("503");
    }

    [Fact]
    public async Task Returns_Unhealthy_when_discovery_endpoint_throws()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var handler = new ThrowingHttpMessageHandler(new HttpRequestException("connection refused"));
        factory.CreateClient("entra-token-relay").Returns(new HttpClient(handler));

        var check = new EntraConnectivityHealthCheck(factory, MakeOptions());

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Exception.Should().NotBeNull();
    }

    // ── helper handlers ──────────────────────────────────────────────────────

    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _code;
        public FakeHttpMessageHandler(HttpStatusCode code) => _code = code;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(_code));
    }

    private sealed class ThrowingHttpMessageHandler : HttpMessageHandler
    {
        private readonly Exception _ex;
        public ThrowingHttpMessageHandler(Exception ex) => _ex = ex;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(_ex);
    }
}
