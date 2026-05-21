using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;
using Xunit.Abstractions;

namespace EntraMcpProxy.IntegrationTests;

/// <summary>
/// Empirical probe: does ModelContextProtocol 0.7.0-preview.1 HttpClientTransport
/// re-attach the Authorization header on every HTTP request, or pin it at
/// session establishment?
///
/// Test methodology:
///   1. Spin up a minimal in-memory ASP.NET Core server hosting a real MCP server via
///      MapMcp() (this correctly implements Streamable HTTP). A recording middleware
///      captures every inbound Authorization header and JSON-RPC method into
///      RecordedHeaders.
///   2. Construct a real McpClient over HttpClientTransport against that server.
///      The HttpClient carries a DelegatingHandler that injects the Authorization
///      header from an AsyncLocal&lt;string?&gt;.
///   3. Set AsyncLocal to "alice-token", call ListToolsAsync(). Record what the
///      server observed.
///   4. Set AsyncLocal to "bob-token", call CallToolAsync("ping"). Record what the
///      server observed.
///   5. Classify:
///      - Both "Bearer alice-token" AND "Bearer bob-token" appear → PER-REQUEST
///      - Only "Bearer alice-token" appears → PER-SESSION
///      - Any other outcome → UNEXPECTED
///
/// Phase 8 shape depends on this finding. See docs/sdk-transport-probe-result.md.
/// </summary>
public sealed class SdkTransportProbeTests
{
    private static readonly AsyncLocal<string?> CurrentBearer = new();

    private readonly ITestOutputHelper _output;

    public SdkTransportProbeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact(Timeout = 30_000)]
    public async Task Determines_per_request_vs_per_session_authorization_semantics()
    {
        // -----------------------------------------------------------------------
        // 1. Build the recording MCP server in-process using ASP.NET Core TestServer.
        //    Middleware records Authorization on each POST request.
        // -----------------------------------------------------------------------
        var recordedHeaders = new ConcurrentQueue<(string Path, string? Authorization, string? Body)>();

        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddMcpServer(opts =>
                    {
                        opts.ServerInfo = new Implementation { Name = "probe-server", Version = "0.0.0" };
                    })
                    .WithHttpTransport()
                    .WithListToolsHandler((req, ct) =>
                    {
                        return new ValueTask<ListToolsResult>(new ListToolsResult
                        {
                            Tools = new List<Tool>
                            {
                                new Tool { Name = "ping", Description = "Returns pong." },
                            }
                        });
                    })
                    .WithCallToolHandler((req, ct) =>
                    {
                        return new ValueTask<CallToolResult>(new CallToolResult
                        {
                            Content = new List<ContentBlock>
                            {
                                new TextContentBlock { Text = "pong" },
                            }
                        });
                    });
                });
                webHost.Configure(app =>
                {
                    // Recording middleware: capture Authorization from every POST.
                    app.Use(async (ctx, next) =>
                    {
                        if (ctx.Request.Method == "POST")
                        {
                            // Buffer body so we can read method name later if desired.
                            ctx.Request.EnableBuffering();
                            var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
                            var path = ctx.Request.Path.ToString();
                            recordedHeaders.Enqueue((path, auth, null));
                        }
                        await next();
                    });

                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapMcp());
                });
            });

        using var host = await hostBuilder.StartAsync();
        var testServer = host.GetTestServer();

        // -----------------------------------------------------------------------
        // 2. Build the McpClient with an AsyncLocal-driven DelegatingHandler.
        // -----------------------------------------------------------------------
        var innerHandler = testServer.CreateHandler();
        var handler = new BearerInjector(() => CurrentBearer.Value, innerHandler);
        using var http = new HttpClient(handler) { BaseAddress = testServer.BaseAddress };

        var transport = new HttpClientTransport(
            new HttpClientTransportOptions { Endpoint = testServer.BaseAddress },
            httpClient: http,
            loggerFactory: null,
            ownsHttpClient: false);

        await using var client = await McpClient.CreateAsync(
            transport,
            new McpClientOptions
            {
                ClientInfo = new Implementation { Name = "probe-client", Version = "0.0.0" },
            });

        // -----------------------------------------------------------------------
        // 3. Call 1: alice — tools/list
        // -----------------------------------------------------------------------
        CurrentBearer.Value = "alice-token";
        await client.ListToolsAsync(options: null, cancellationToken: default);

        // -----------------------------------------------------------------------
        // 4. Call 2: bob — tools/call
        // -----------------------------------------------------------------------
        CurrentBearer.Value = "bob-token";
        await client.CallToolAsync(
            new CallToolRequestParams { Name = "ping" },
            cancellationToken: default);

        // -----------------------------------------------------------------------
        // 5. Analyse results
        // -----------------------------------------------------------------------
        var allCalls = recordedHeaders.ToArray();
        _output.WriteLine($"Recorded {allCalls.Length} server-side POST requests:");
        foreach (var (path, auth, _) in allCalls)
        {
            _output.WriteLine($"  path={path} authorization={auth ?? "<null>"}");
        }

        // Filter to only the calls that happened after McpClient.CreateAsync
        // (which sends initialize + notifications/initialized). We want the
        // tool-related calls only. We know alice's call came first, bob's second.
        // Take the last two non-null Authorization entries among POSTs.
        var authOnly = allCalls
            .Where(c => c.Authorization != null)
            .Select(c => c.Authorization!)
            .ToArray();

        _output.WriteLine($"Authorization values observed: [{string.Join(", ", authOnly)}]");

        var hasAlice = authOnly.Any(a => a == "Bearer alice-token");
        var hasBob   = authOnly.Any(a => a == "Bearer bob-token");
        var distinctAuths = authOnly.Distinct().ToArray();

        if (hasAlice && hasBob)
        {
            _output.WriteLine("RESULT: PER-REQUEST semantics — Authorization is re-attached per HTTP call.");
            _output.WriteLine("        Phase 8 keeps singleton McpClient per downstream.");
            hasAlice.Should().BeTrue("alice's bearer must reach the server when set during her call");
            hasBob.Should().BeTrue("bob's bearer must reach the server when set during his call");
        }
        else if (hasAlice && !hasBob)
        {
            _output.WriteLine("RESULT: PER-SESSION semantics — Authorization is pinned at session establishment.");
            _output.WriteLine("        Phase 8 requires per-user McpClient lifecycle.");
            throw new Xunit.Sdk.XunitException(
                "PER-SESSION semantics detected. Phase 8 must implement per-user client lifecycle. " +
                $"Recorded authorizations: [{string.Join(", ", distinctAuths)}]");
        }
        else
        {
            _output.WriteLine($"RESULT: UNEXPECTED — authorizations seen: [{string.Join(", ", distinctAuths)}]");
            throw new Xunit.Sdk.XunitException(
                $"Unexpected probe outcome. AsyncLocal flow may not work as expected inside the SDK. " +
                $"Authorizations seen: [{string.Join(", ", distinctAuths)}]. Investigate before Phase 8.");
        }

        await host.StopAsync();
    }

    /// <summary>
    /// DelegatingHandler that injects an Authorization: Bearer header on every
    /// outbound request, reading the token from the supplied factory. The factory
    /// is called at send-time (not construction-time) so that AsyncLocal values
    /// are captured in the correct async context.
    /// </summary>
    private sealed class BearerInjector : DelegatingHandler
    {
        private readonly Func<string?> _getBearer;

        public BearerInjector(Func<string?> getBearer, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            _getBearer = getBearer;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? bearer = _getBearer();
            if (!string.IsNullOrEmpty(bearer))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }
            return base.SendAsync(request, cancellationToken);
        }
    }
}
