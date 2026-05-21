using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.IntegrationTests.Fixtures;
using EntraMcpProxy.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// CRITICAL audit finding C2: with a singleton McpClient per downstream
/// (Phase 2 confirmed per-request Authorization semantics), two concurrent
/// users must receive their OWN OBO-exchanged tokens at the downstream —
/// never each other's.
///
/// Architecture:
///   alice/bob ──→ proxy (WebApplicationFactory)
///                   │
///                   │  OBO: exchanges inbound JWT for per-user downstream token
///                   ↓
///              recording MCP TestServer (ASP.NET Core in-process, MapMcp)
///              recording all inbound Authorization headers
///
/// FakeEntra's token endpoint is configured dynamically to embed a fingerprint
/// of the OBO assertion in the returned access_token, so alice's and bob's
/// distinct user JWTs always produce distinct downstream tokens.
///
/// The key architectural detail: the proxy's DownstreamClientManager holds a
/// SINGLETON McpClient per downstream. When alice calls tools/call and then bob
/// calls tools/call, both use the same McpClient but IHttpContextAccessor
/// provides the correct per-request user context to EntraIdOBOHandler — the
/// OBO cache is keyed on (oid, tid, aud, scope) via OboCacheKey, not on the
/// raw token, so there is no cross-user collision.
///
/// After N concurrent calls from each user the recording downstream must show
/// exactly 2 distinct Authorization header values — one per user.
/// </summary>
public class TwoUserConcurrencyTests
{
    private const int CallsPerUser = 10;
    private const string ProxyClientId = "33333333-3333-3333-3333-333333333333";

    [Fact(Timeout = 120_000)]
    public async Task Two_concurrent_users_get_their_own_OBO_tokens()
    {
        var tenantId = Guid.NewGuid().ToString();

        // FakeEntra: issues JWTs validated by the proxy; handles OBO exchanges.
        // Audience = ProxyClientId so proxy JwtBearer check passes.
        await using var entra = new FakeEntra(tenantId, audience: ProxyClientId);

        // Recording downstream MCP server: a real ASP.NET Core TestServer with
        // MapMcp(). Records the Authorization header on every inbound MCP request.
        var recordedAuths = new ConcurrentBag<(string Method, string? Auth)>();
        using var downstreamHost = await BuildRecordingDownstreamAsync(recordedAuths);
        var downstreamTestServer = downstreamHost.GetTestServer();

        // Dynamic FakeEntra token endpoint:
        //   client_credentials → static SP discovery token
        //   jwt-bearer (OBO)   → fingerprint of assertion embedded in token
        entra.RegisterTokenEndpointHandler(body =>
        {
            if (string.Equals(ParseFormField(body, "grant_type"), "client_credentials"))
                return new { access_token = "discovery-sp-token", token_type = "Bearer", expires_in = 3600 };

            var assertion   = ParseFormField(body, "assertion") ?? "";
            var fingerprint = assertion.Length >= 10
                ? assertion[^10..].Replace('+', '-').Replace('/', '_').Replace('=', 'x')
                : "short";
            return new { access_token = $"obo-{fingerprint}", token_type = "Bearer", expires_in = 3600 };
        });

        var aliceToken = entra.IssueUserToken(oid: "alice-oid");
        var bobToken   = entra.IssueUserToken(oid:   "bob-oid");
        aliceToken.Should().NotBe(bobToken);

        // Build proxy factory that injects the TestServer downstream handler into
        // DownstreamClientManager so the proxy connects to the in-process MCP server.
        await using var factory = new ConcurrencyFactory(entra, downstreamTestServer, ProxyClientId);

        // Wait for ToolAggregatorService startup to register fake__ping.
        await WaitForToolRegistrationAsync(factory, aliceToken, timeoutMs: 30_000);

        // ─── concurrent calls from both users ──────────────────────────────────
        await using var aliceClient = await CreateProxyMcpClientAsync(factory, aliceToken);
        await using var bobClient   = await CreateProxyMcpClientAsync(factory,   bobToken);

        var aliceTasks = Enumerable.Range(0, CallsPerUser)
            .Select(_ => aliceClient.CallToolAsync(
                new CallToolRequestParams { Name = "fake__ping" }).AsTask());
        var bobTasks = Enumerable.Range(0, CallsPerUser)
            .Select(_ => bobClient.CallToolAsync(
                new CallToolRequestParams { Name = "fake__ping" }).AsTask());

        await Task.WhenAll(aliceTasks.Concat(bobTasks));

        // ─── C2 closure assertions ─────────────────────────────────────────────
        var toolCalls = recordedAuths
            .Where(x => x.Method == "tools/call")
            .ToList();

        toolCalls.Should().HaveCount(2 * CallsPerUser,
            $"all tools/call requests must reach the downstream; got {toolCalls.Count}");

        var distinctAuths = toolCalls
            .Select(x => x.Auth)
            .Where(a => a is not null)
            .Distinct()
            .ToList();

        distinctAuths.Should().HaveCount(2,
            "two users must produce two distinct downstream OBO tokens — never crosstalk. " +
            $"Actual: [{string.Join(", ", distinctAuths)}]");

        toolCalls.Should().AllSatisfy(x =>
            x.Auth.Should().NotBeNullOrEmpty("every downstream call must carry an Authorization header"));

        await downstreamHost.StopAsync();
    }

    // ── recording downstream MCP server ──────────────────────────────────────

    private static async Task<IHost> BuildRecordingDownstreamAsync(
        ConcurrentBag<(string Method, string? Auth)> bag)
    {
        var builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddMcpServer(opts =>
                    {
                        opts.ServerInfo = new Implementation
                        {
                            Name = "recording-downstream", Version = "0.0.1"
                        };
                        opts.Capabilities = new() { Tools = new() { } };
                    })
                    .WithHttpTransport()
                    .WithListToolsHandler((_, _) => new ValueTask<ListToolsResult>(
                        new ListToolsResult
                        {
                            Tools = new List<Tool>
                            {
                                new() { Name = "ping", Description = "Returns pong." }
                            }
                        }))
                    .WithCallToolHandler((_, _) => new ValueTask<CallToolResult>(
                        new CallToolResult
                        {
                            Content = new List<ContentBlock> { new TextContentBlock { Text = "pong" } }
                        }));
                });
                webHost.Configure(app =>
                {
                    // Recording middleware — runs before MapMcp.
                    app.Use(async (ctx, next) =>
                    {
                        if (ctx.Request.Method == "POST")
                        {
                            ctx.Request.EnableBuffering();
                            var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();

                            string method = "unknown";
                            try
                            {
                                ctx.Request.Body.Position = 0;
                                using var rdr = new System.IO.StreamReader(
                                    ctx.Request.Body, Encoding.UTF8, leaveOpen: true);
                                var body = await rdr.ReadToEndAsync();
                                ctx.Request.Body.Position = 0;

                                if      (body.Contains("\"tools/call\""))    method = "tools/call";
                                else if (body.Contains("\"tools/list\""))    method = "tools/list";
                                else if (body.Contains("\"initialize\""))    method = "initialize";
                                else if (body.Contains("\"notifications\"")) method = "notification";
                            }
                            catch { /* best-effort */ }

                            bag.Add((method, auth));
                        }
                        await next();
                    });
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapMcp());
                });
            });

        return await builder.StartAsync();
    }

    // ── McpClient helpers ─────────────────────────────────────────────────────

    private static async Task<McpClient> CreateProxyMcpClientAsync(
        ConcurrencyFactory factory, string bearerToken)
    {
        var inner   = factory.Server.CreateHandler();
        var handler = new FixedBearerHandler(bearerToken, inner);
        var http    = new HttpClient(handler) { BaseAddress = factory.Server.BaseAddress };

        return await McpClient.CreateAsync(
            new HttpClientTransport(
                new HttpClientTransportOptions { Endpoint = factory.Server.BaseAddress },
                http, loggerFactory: null, ownsHttpClient: false),
            new McpClientOptions
            {
                ClientInfo = new Implementation { Name = "test-client", Version = "0.0.1" }
            });
    }

    private sealed class FixedBearerHandler : DelegatingHandler
    {
        private readonly string _token;
        public FixedBearerHandler(string token, HttpMessageHandler inner) : base(inner) => _token = token;
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage req, CancellationToken ct)
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            return base.SendAsync(req, ct);
        }
    }

    // ── startup wait ──────────────────────────────────────────────────────────

    private static async Task WaitForToolRegistrationAsync(
        ConcurrencyFactory factory, string bearerToken, int timeoutMs)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                await using var client = await CreateProxyMcpClientAsync(factory, bearerToken);
                var tools = await client.ListToolsAsync();
                if (tools.Any(t => t.Name == "fake__ping")) return;
            }
            catch { /* not ready yet */ }
            await Task.Delay(300);
        }
        throw new TimeoutException(
            $"Timed out ({timeoutMs}ms) waiting for 'fake__ping' in proxy tool registry. " +
            "Check ToolAggregatorService startup: DiscoveryScope must be set and FakeEntra must respond.");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static string? ParseFormField(string body, string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            var k = Uri.UnescapeDataString(pair[..eq].Replace('+', ' '));
            if (!string.Equals(k, name, StringComparison.OrdinalIgnoreCase)) continue;
            return Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
        }
        return null;
    }

    // ── ConcurrencyFactory ────────────────────────────────────────────────────

    /// <summary>
    /// ProxyAppFactory that:
    ///   - wires EntraId → FakeEntra
    ///   - replaces DownstreamClientManager with a test subclass that routes the
    ///     downstream McpClient through the recording in-process TestServer
    ///   - configures OBO with FakeEntra token endpoint and DiscoveryScope
    /// </summary>
    private sealed class ConcurrencyFactory : ProxyAppFactory
    {
        private readonly FakeEntra _entra;
        private readonly TestServer _downstreamTestServer;
        private readonly string _clientId;

        public ConcurrencyFactory(FakeEntra entra, TestServer downstreamTestServer, string clientId)
        {
            _entra = entra;
            _downstreamTestServer = downstreamTestServer;
            _clientId = clientId;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            var downstreamTestServer = _downstreamTestServer; // capture for lambda

            builder.ConfigureAppConfiguration((_, cfg) =>
            {
                // "fake" downstream base URL — used only for config shape validation
                // (must be in EgressAllowlist); the actual connection uses the TestServer handler.
                const string fakeDownstreamUrl = "http://downstream.test/";

                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["EntraId:Authority"]            = _entra.Issuer,
                    ["EntraId:TenantId"]             = _entra.TenantId,
                    ["EntraId:ClientId"]             = _clientId,
                    ["EntraId:RequireHttpsMetadata"] = "false",

                    ["DownstreamServers:0:Name"]    = "fake",
                    ["DownstreamServers:0:Prefix"]  = "fake",
                    ["DownstreamServers:0:BaseUrl"] = fakeDownstreamUrl,
                    ["DownstreamServers:0:AuthType"] = "OBOToken",
                    ["DownstreamServers:0:Enabled"]  = "true",
                    ["DownstreamServers:0:OBO:TenantId"]             = _entra.TenantId,
                    ["DownstreamServers:0:OBO:ClientId"]             = "22222222-2222-2222-2222-222222222222",
                    ["DownstreamServers:0:OBO:ClientSecret"]         = "test-secret-not-real",
                    ["DownstreamServers:0:OBO:TargetScope"]          = "api://fake/.default",
                    ["DownstreamServers:0:OBO:DiscoveryScope"]       = "api://fake/Discovery.Tools",
                    ["DownstreamServers:0:OBO:TokenEndpointBaseUrl"] = _entra.Url,
                });
            });

            builder.ConfigureServices(services =>
            {
                // Remove the standard DownstreamClientManager singleton and replace with
                // a test-aware subclass that injects the TestServer's in-process handler
                // into the downstream McpClient pipeline.
                services.AddSingleton<DownstreamClientManager>(sp =>
                    new InProcessDownstreamClientManager(
                        sp.GetRequiredService<IOptions<List<DownstreamServerOptions>>>(),
                        sp.GetRequiredService<ILoggerFactory>(),
                        sp.GetRequiredService<IHttpContextAccessor>(),
                        downstreamTestServer));
            });
        }
    }

    /// <summary>
    /// DownstreamClientManager subclass that routes the downstream HTTP connection
    /// through the recording TestServer's in-process handler rather than making
    /// real TCP connections. The OBO DelegatingHandler chain is preserved — only
    /// the innermost (real network) handler is replaced with the TestServer handler.
    /// </summary>
    private sealed class InProcessDownstreamClientManager : DownstreamClientManager
    {
        private readonly TestServer _testServer;

        public InProcessDownstreamClientManager(
            IOptions<List<DownstreamServerOptions>> configs,
            ILoggerFactory loggerFactory,
            IHttpContextAccessor httpContextAccessor,
            TestServer testServer)
            : base(configs, loggerFactory, httpContextAccessor)
        {
            _testServer = testServer;
        }

        protected override HttpClient CreateHttpClient(DownstreamServerOptions config)
        {
            if (string.Equals(config.AuthType, "OBOToken", StringComparison.OrdinalIgnoreCase))
            {
                var obo = config.OBO!;

                // Inner handler = TestServer's in-process handler (no real TCP needed)
                var innerHandler = _testServer.CreateHandler();

                var oboHandler = new EntraIdOBOHandler(
                    _httpContextAccessor,
                    obo.TenantId, obo.ClientId, obo.ClientSecret, obo.TargetScope,
                    _loggerFactory.CreateLogger<EntraIdOBOHandler>(),
                    innerHandler: innerHandler,
                    discoveryScope: obo.DiscoveryScope,
                    tokenEndpointBaseUrl: obo.TokenEndpointBaseUrl);

                return new HttpClient(oboHandler, disposeHandler: true)
                {
                    Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds),
                    BaseAddress = _testServer.BaseAddress,
                };
            }

            return base.CreateHttpClient(config);
        }
    }
}
