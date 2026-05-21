using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using EntraMcpProxy.Services;
using FluentAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

/// <summary>
/// Unit tests for DownstreamConnectivityHealthCheck.
///
/// Uses a <see cref="StubClientManager"/> that overrides the virtual
/// <c>GetAllClients()</c> to simulate connected/disconnected states
/// without real network connections.
/// </summary>
public class DownstreamConnectivityHealthCheckTests
{
    private static HealthCheckContext MakeContext() =>
        new() { Registration = new HealthCheckRegistration("test", _ => throw new InvalidOperationException(), null, null) };

    [Fact]
    public async Task Healthy_when_no_downstream_servers_configured()
    {
        // Arrange: empty config list → no configs, no connections
        var manager = new StubClientManager(configs: [], fakeConnectedCount: 0);
        var check = new DownstreamConnectivityHealthCheck(manager);

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("No downstream servers configured");
    }

    [Fact]
    public async Task Degraded_when_configured_but_zero_connected()
    {
        // Arrange: 1 config, 0 connections (startup / lazy-connect)
        var configs = new List<DownstreamServerOptions>
        {
            new() { Name = "svc1", Prefix = "svc1", BaseUrl = "https://svc1.test", Enabled = true },
        };
        var manager = new StubClientManager(configs, fakeConnectedCount: 0);
        var check = new DownstreamConnectivityHealthCheck(manager);

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("lazy-connect");
    }

    [Fact]
    public async Task Healthy_with_count_when_all_configured_are_connected()
    {
        // Arrange: 2 configs, 2 connections
        var configs = new List<DownstreamServerOptions>
        {
            new() { Name = "svc1", Prefix = "svc1", BaseUrl = "https://svc1.test", Enabled = true },
            new() { Name = "svc2", Prefix = "svc2", BaseUrl = "https://svc2.test", Enabled = true },
        };
        var manager = new StubClientManager(configs, fakeConnectedCount: 2);
        var check = new DownstreamConnectivityHealthCheck(manager);

        // Act
        var result = await check.CheckHealthAsync(MakeContext());

        // Assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("2/2");
    }

    // ── helper ───────────────────────────────────────────────────────────────

    private sealed class StubClientManager : DownstreamClientManager
    {
        private readonly int _fakeConnectedCount;

        public StubClientManager(List<DownstreamServerOptions> configs, int fakeConnectedCount)
            : base(
                Options.Create(configs),
                LoggerFactory.Create(_ => { }),
                httpContextAccessor: null!,
                audit: null!,
                serviceProvider: null!,
                httpClientFactory: null!)
        {
            _fakeConnectedCount = fakeConnectedCount;
        }

        // Override virtual method to simulate connection state.
        public override IReadOnlyList<(string Prefix, ModelContextProtocol.Client.McpClient Client)>
            GetAllClients() =>
            Enumerable
                .Range(0, _fakeConnectedCount)
                .Select(i => ($"svc{i}", (ModelContextProtocol.Client.McpClient)null!))
                .ToList();
    }
}
