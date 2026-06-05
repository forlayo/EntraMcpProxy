using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;
using DotNet.Testcontainers.Networks;
using Xunit;

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
///
/// Bootstrap stubs are seeded before the proxy starts so that ToolAggregatorService
/// can complete its startup SP-discovery exchange (client_credentials) and
/// McpClient.CreateAsync can send its MCP initialize handshake to the downstream.
/// Individual tests layer additional or more specific mappings on top.
/// </summary>
public sealed class ProxyContainerFixture : IAsyncLifetime
{
    private const string ProxyImage = "entra-mcp-proxy:e2e";
    private const int ProxyPort = 8080;
    private static readonly TimeSpan ContainerWaitTimeout = TimeSpan.FromMinutes(3);
    // Pinned by digest for supply-chain hygiene. Tag '3.9.1' is preserved in the comment
    // for human readability; the digest is authoritative. Rotate both when bumping versions.
    // Source: docker inspect wiremock/wiremock:3.9.1 (resolved during Task 1.5 follow-up).
    private const string WireMockImage = "wiremock/wiremock@sha256:8fe02bc3f9b63deb1454d41750dbaf081adf4b3e8c74fd8e31f790bee5647b88";

    internal const string FakeTenantId = "00000000-0000-0000-0000-000000000001";
    internal const string FakeClientId = "00000000-0000-0000-0000-000000000002";

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
        await fx.InitializeAsync();
        return fx;
    }

    public Task InitializeAsync() => InitAsync();

    private async Task InitAsync()
    {
        // 1. Build the proxy image from the repo Dockerfile.
        _proxyImage = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(ResolveRepositoryRoot())
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
                .UntilHttpRequestIsSucceeded(
                    r => r.ForPort(8080).ForPath("/__admin/mappings"),
                    w => w.WithTimeout(ContainerWaitTimeout)))
            .Build();
        await _entra.StartAsync().ConfigureAwait(false);
        EntraAdminUrl = $"http://{_entra.Hostname}:{_entra.GetMappedPublicPort(8080)}/__admin";

        // Pre-configure WireMock-Entra with a catch-all token stub so the proxy's
        // ToolAggregatorService can complete its startup SP discovery exchange before
        // individual tests layer their own more specific mappings.
        await SeedDefaultEntraTokenStubAsync(EntraAdminUrl).ConfigureAwait(false);

        // 4. WireMock for fake downstream MCP. Network alias = "downstream".
        //    Per-mapping "transformers":["ResponseTemplateTransformer"] is used on
        //    individual stubs to enable Handlebars id-echoing; no global flag needed.
        _downstream = new ContainerBuilder()
            .WithImage(WireMockImage)
            .WithNetwork(_network)
            .WithNetworkAliases("downstream")
            .WithPortBinding(8080, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(
                    r => r.ForPort(8080).ForPath("/__admin/mappings"),
                    w => w.WithTimeout(ContainerWaitTimeout)))
            .Build();
        await _downstream.StartAsync().ConfigureAwait(false);
        DownstreamAdminUrl = $"http://{_downstream.Hostname}:{_downstream.GetMappedPublicPort(8080)}/__admin";

        // Pre-configure WireMock-downstream with MCP session lifecycle stubs so that
        // McpClient.CreateAsync (initialize) and ListToolsAsync (tools/list) succeed
        // during proxy startup tool discovery.
        await SeedDefaultDownstreamStubsAsync(DownstreamAdminUrl).ConfigureAwait(false);

        // 5. The proxy. Configuration is supplied entirely via env vars so the
        //    image itself stays generic.
        _proxy = new ContainerBuilder()
            .WithImage(ProxyImage)
            .WithNetwork(_network)
            // Use E2ETest environment so the Production startup guard (finding N18)
            // does not fire — E2E tests use a fake HTTP Entra that requires
            // RequireHttpsMetadata=false for JWT bearer to accept the HTTP authority.
            .WithEnvironment("ASPNETCORE_ENVIRONMENT", "E2ETest")
            .WithEnvironment("ASPNETCORE_URLS", $"http://+:{ProxyPort}")
            .WithEnvironment("EntraId__Authority", $"http://entra:8080/{FakeTenantId}/v2.0")
            .WithEnvironment("EntraId__TenantId",   FakeTenantId)
            .WithEnvironment("EntraId__ClientId",   FakeClientId)
            .WithEnvironment("EntraId__RequireHttpsMetadata", "false")
            // ProxyOptions validator requires PublicBaseUrl (https), at least one
            // AllowedRedirectUri, and at least one EgressAllowlist host.
            .WithEnvironment("Proxy__PublicBaseUrl", "https://proxy.e2etest.local")
            .WithEnvironment("Proxy__AllowedRedirectUris__0", "https://claude.ai/api/mcp/auth_callback")
            .WithEnvironment("Proxy__EgressAllowlist__0", "downstream")
            .WithEnvironment("DownstreamServers__0__Name",    "fake-downstream")
            .WithEnvironment("DownstreamServers__0__Prefix",  "fake")
            .WithEnvironment("DownstreamServers__0__BaseUrl", "http://downstream:8080")
            .WithEnvironment("DownstreamServers__0__AuthType","OBOToken")
            .WithEnvironment("DownstreamServers__0__OBO__TenantId",    FakeTenantId)
            .WithEnvironment("DownstreamServers__0__OBO__ClientId",    FakeClientId)
            .WithEnvironment("DownstreamServers__0__OBO__ClientSecret","test-secret-not-real")
            .WithEnvironment("DownstreamServers__0__OBO__TargetScope",
                "00000000-0000-0000-0000-000000000099/Ado.Mcp.Tools")
            // TokenEndpointBaseUrl redirects OBO and SP token exchanges to the
            // WireMock-Entra container (on the Docker network) instead of the real
            // login.microsoftonline.com, making E2E tests hermetic.
            .WithEnvironment("DownstreamServers__0__OBO__TokenEndpointBaseUrl",
                "http://entra:8080")
            // DiscoveryScope enables the SP (client_credentials) fallback in
            // ToolAggregatorService so that tool discovery at startup can obtain a
            // token even before any user makes a request.
            .WithEnvironment("DownstreamServers__0__OBO__DiscoveryScope",
                "00000000-0000-0000-0000-000000000099/Discovery.Tools")
            .WithEnvironment("DownstreamServers__0__Enabled", "true")
            .WithPortBinding(ProxyPort, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(
                    r => r.ForPort(ProxyPort).ForPath("/api/healthz"),
                    w => w.WithTimeout(ContainerWaitTimeout)))
            .Build();
        await _proxy.StartAsync().ConfigureAwait(false);

        Http = new HttpClient
        {
            BaseAddress = new Uri($"http://{_proxy.Hostname}:{_proxy.GetMappedPublicPort(ProxyPort)}/"),
        };
    }

    internal static string ResolveRepositoryRoot()
    {
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("ENTRA_MCP_PROXY_REPOSITORY_ROOT"),
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
        };

        foreach (var candidate in candidates.Where(c => !string.IsNullOrWhiteSpace(c)))
        {
            var dir = new DirectoryInfo(Path.GetFullPath(candidate!));
            while (dir is not null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "EntraMcpProxy.sln")) &&
                    File.Exists(Path.Combine(dir.FullName, "Dockerfile")))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }
        }

        throw new DirectoryNotFoundException(
            "Cannot resolve the repository root. Set ENTRA_MCP_PROXY_REPOSITORY_ROOT " +
            "to the directory containing EntraMcpProxy.sln and Dockerfile.");
    }

    /// <summary>
    /// Seeds WireMock-Entra with a low-priority catch-all token stub that returns a
    /// generic access token for any POST to the tenant token endpoint.
    ///
    /// This lets the proxy's ToolAggregatorService complete its startup
    /// client_credentials (SP) discovery exchange against WireMock rather than the
    /// real login.microsoftonline.com. Individual tests replace this with higher-
    /// priority stubs that return scenario-specific tokens.
    /// </summary>
    private static async Task SeedDefaultEntraTokenStubAsync(string adminUrl)
    {
        using var http = new HttpClient { BaseAddress = new Uri(adminUrl + "/") };

        // Catch-all token endpoint: matches ANY POST to /{tenantId}/oauth2/v2.0/token.
        // Priority = 10 (low) so individual test mappings (priority 1, the default) take precedence.
        var mapping = new
        {
            priority = 10,
            request = new
            {
                method = "POST",
                urlPattern = $"/{FakeTenantId}/oauth2/v2.0/token",
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                jsonBody = new
                {
                    access_token = "default-startup-token",
                    token_type = "Bearer",
                    expires_in = 3600,
                },
            },
        };

        var json = JsonSerializer.Serialize(mapping);
        using var resp = await http.PostAsync("mappings",
            new StringContent(json, Encoding.UTF8, "application/json"));
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Seeds WireMock-downstream with low-priority MCP lifecycle stubs so that
    /// McpClient.CreateAsync (initialize) and the discovery ListToolsAsync call
    /// succeed during proxy startup.
    ///
    /// Individual tests may post higher-priority or additional mappings on top of
    /// these defaults without resetting them.
    ///
    /// Response bodies use the Handlebars {{jsonPath}} helper to echo the JSON-RPC
    /// request id back in the response.  The per-mapping "transformers" field enables
    /// response templating for that mapping without requiring the container-level
    /// --global-response-templating flag.
    ///
    /// Body matching uses "matchesJsonPath" (exact field value) instead of "contains"
    /// to avoid the stub for "initialize" accidentally matching bodies that contain the
    /// substring "initialize" as part of another method name (e.g. "notifications/initialized").
    /// </summary>
    private static async Task SeedDefaultDownstreamStubsAsync(string adminUrl)
    {
        using var http = new HttpClient { BaseAddress = new Uri(adminUrl + "/") };

        // notifications/initialized — fire-and-forget notification the MCP SDK sends
        // after the initialize handshake completes.  No id field; WireMock must return
        // 200 so the SDK does not treat the notification as a failure.
        var notif = new
        {
            priority = 10,
            request = new
            {
                method = "POST",
                url = "/",
                bodyPatterns = new[] { new { matchesJsonPath = "$..[?(@.method == 'notifications/initialized')]" } },
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                body = "{}",
            },
        };
        await PostMappingAsync(http, notif);

        // initialize — MCP session handshake.
        // Uses a Handlebars template body with the per-mapping ResponseTemplateTransformer
        // to echo back the request's JSON-RPC id dynamically.
        var init = new
        {
            priority = 10,
            request = new
            {
                method = "POST",
                url = "/",
                bodyPatterns = new[] { new { matchesJsonPath = "$..[?(@.method == 'initialize')]" } },
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                body = "{\"jsonrpc\":\"2.0\",\"id\":{{jsonPath request.body '$.id'}},\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"e2e-fake-default\",\"version\":\"0.0.1\"}}}",
                // WireMock Java (Docker) uses "response-template" (not .NET's "ResponseTemplateTransformer")
                transformers = new[] { "response-template" },
            },
        };
        await PostMappingAsync(http, init);

        // tools/list — startup discovery tool catalog (one stub ping tool)
        var list = new
        {
            priority = 10,
            request = new
            {
                method = "POST",
                url = "/",
                bodyPatterns = new[] { new { matchesJsonPath = "$..[?(@.method == 'tools/list')]" } },
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                body = "{\"jsonrpc\":\"2.0\",\"id\":{{jsonPath request.body '$.id'}},\"result\":{\"tools\":[{\"name\":\"ping\",\"description\":\"Returns pong.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]}}",
                transformers = new[] { "response-template" },
            },
        };
        await PostMappingAsync(http, list);

        // tools/call — default handler for any call
        var call = new
        {
            priority = 10,
            request = new
            {
                method = "POST",
                url = "/",
                bodyPatterns = new[] { new { matchesJsonPath = "$..[?(@.method == 'tools/call')]" } },
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                body = "{\"jsonrpc\":\"2.0\",\"id\":{{jsonPath request.body '$.id'}},\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"pong\"}],\"isError\":false}}",
                transformers = new[] { "response-template" },
            },
        };
        await PostMappingAsync(http, call);
    }

    private static async Task PostMappingAsync(HttpClient http, object mapping)
    {
        var json = JsonSerializer.Serialize(mapping);
        using var resp = await http.PostAsync("mappings",
            new StringContent(json, Encoding.UTF8, "application/json"));
        resp.EnsureSuccessStatusCode();
    }

    public async Task DisposeAsync()
    {
        Http?.Dispose();
        if (_proxy      is not null) await _proxy.DisposeAsync().ConfigureAwait(false);
        if (_downstream is not null) await _downstream.DisposeAsync().ConfigureAwait(false);
        if (_entra      is not null) await _entra.DisposeAsync().ConfigureAwait(false);
        if (_network    is not null) await _network.DisposeAsync().ConfigureAwait(false);
        // The image is kept across runs to speed up subsequent test sessions.
    }
}
