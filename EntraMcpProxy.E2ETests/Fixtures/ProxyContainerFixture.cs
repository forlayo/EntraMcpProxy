using System;
using System.Net.Http;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;
using DotNet.Testcontainers.Networks;

namespace EntraMcpProxy.E2ETests.Fixtures;

/// <summary>
/// Boots the EntraMcpProxy Docker image alongside placeholder WireMock containers
/// for fake Entra (OIDC) and fake downstream MCP, on a private Docker network.
///
/// The fixture exposes the proxy's published HTTP port via <see cref="Http"/>.
/// Tests interact with the proxy entirely through HTTP — no in-process types.
///
/// Per the plan, the proxy image is built from the repo's Dockerfile and the
/// WireMock containers run with default empty mappings; tests that need
/// specific Entra or downstream behavior should layer mappings via the
/// WireMock admin API at <see cref="EntraAdminUrl"/> and
/// <see cref="DownstreamAdminUrl"/>.
/// </summary>
public sealed class ProxyContainerFixture : IAsyncDisposable
{
    private const string ProxyImage = "entra-mcp-proxy:e2e";
    private const string WireMockImage = "wiremock/wiremock:3.9.1";

    private IFutureDockerImage? _proxyImage;
    private INetwork? _network;
    private IContainer? _entra;
    private IContainer? _downstream;
    private IContainer? _proxy;

    /// <summary>HttpClient pointed at the proxy's published port.</summary>
    public HttpClient Http { get; private set; } = default!;

    /// <summary>WireMock admin URL for the fake Entra container (host-side).</summary>
    public string EntraAdminUrl { get; private set; } = default!;

    /// <summary>WireMock admin URL for the fake downstream container (host-side).</summary>
    public string DownstreamAdminUrl { get; private set; } = default!;

    public static async Task<ProxyContainerFixture> StartAsync()
    {
        var fx = new ProxyContainerFixture();
        await fx.InitAsync();
        return fx;
    }

    private async Task InitAsync()
    {
        // 1. Build the proxy image from the repo Dockerfile.
        _proxyImage = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(CommonDirectoryPath.GetSolutionDirectory(), string.Empty)
            .WithDockerfile("Dockerfile")
            .WithName(ProxyImage)
            .Build();
        await _proxyImage.CreateAsync().ConfigureAwait(false);

        // 2. Private Docker network so containers can resolve each other by name.
        _network = new NetworkBuilder().Build();
        await _network.CreateAsync().ConfigureAwait(false);

        // 3. WireMock for fake Entra. Network alias = "entra".
        _entra = new ContainerBuilder()
            .WithImage(WireMockImage)
            .WithNetwork(_network)
            .WithNetworkAliases("entra")
            .WithPortBinding(8080, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(8080).ForPath("/__admin/mappings")))
            .Build();
        await _entra.StartAsync().ConfigureAwait(false);
        EntraAdminUrl = $"http://{_entra.Hostname}:{_entra.GetMappedPublicPort(8080)}/__admin";

        // 4. WireMock for fake downstream MCP. Network alias = "downstream".
        _downstream = new ContainerBuilder()
            .WithImage(WireMockImage)
            .WithNetwork(_network)
            .WithNetworkAliases("downstream")
            .WithPortBinding(8080, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(8080).ForPath("/__admin/mappings")))
            .Build();
        await _downstream.StartAsync().ConfigureAwait(false);
        DownstreamAdminUrl = $"http://{_downstream.Hostname}:{_downstream.GetMappedPublicPort(8080)}/__admin";

        // 5. The proxy. Configuration is supplied entirely via env vars so the
        //    image itself stays generic.
        const string FakeTenantId = "00000000-0000-0000-0000-000000000001";
        const string FakeClientId = "00000000-0000-0000-0000-000000000002";

        _proxy = new ContainerBuilder()
            .WithImage(ProxyImage)
            .WithNetwork(_network)
            .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Production")
            .WithEnvironment("ASPNETCORE_URLS", "http://+:80")
            .WithEnvironment("EntraId__Authority", $"http://entra:8080/{FakeTenantId}/v2.0")
            .WithEnvironment("EntraId__TenantId",   FakeTenantId)
            .WithEnvironment("EntraId__ClientId",   FakeClientId)
            .WithEnvironment("EntraId__RequireHttpsMetadata", "false")
            .WithEnvironment("DownstreamServers__0__Name",    "fake-downstream")
            .WithEnvironment("DownstreamServers__0__Prefix",  "fake")
            .WithEnvironment("DownstreamServers__0__BaseUrl", "http://downstream:8080")
            .WithEnvironment("DownstreamServers__0__AuthType","OBOToken")
            .WithEnvironment("DownstreamServers__0__OBO__TenantId",    FakeTenantId)
            .WithEnvironment("DownstreamServers__0__OBO__ClientId",    FakeClientId)
            .WithEnvironment("DownstreamServers__0__OBO__ClientSecret","test-secret-not-real")
            .WithEnvironment("DownstreamServers__0__OBO__TargetScope",
                "00000000-0000-0000-0000-000000000099/Ado.Mcp.Tools")
            .WithEnvironment("DownstreamServers__0__Enabled", "true")
            .WithPortBinding(80, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(80).ForPath("/api/healthz")))
            .Build();
        await _proxy.StartAsync().ConfigureAwait(false);

        Http = new HttpClient
        {
            BaseAddress = new Uri($"http://{_proxy.Hostname}:{_proxy.GetMappedPublicPort(80)}/"),
        };
    }

    public async ValueTask DisposeAsync()
    {
        Http?.Dispose();
        if (_proxy      is not null) await _proxy.DisposeAsync().ConfigureAwait(false);
        if (_downstream is not null) await _downstream.DisposeAsync().ConfigureAwait(false);
        if (_entra      is not null) await _entra.DisposeAsync().ConfigureAwait(false);
        if (_network    is not null) await _network.DisposeAsync().ConfigureAwait(false);
        // The image is kept across runs to speed up subsequent test sessions.
    }
}
