using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

/// <summary>
/// In-memory fake downstream MCP server, served via WireMock.Net.
///
/// Responds to MCP-over-HTTP JSON-RPC requests:
///   - method "initialize"      → minimal capabilities response
///   - method "tools/list"      → configurable tool catalog (default: a single "ping" tool)
///   - method "tools/call"      → echo-back content; isError=false
///
/// Every received request is recorded into <see cref="RecordedCalls"/> with the
/// inbound Authorization header and the JSON-RPC method, so tests can prove
/// which user's token reached the downstream.
///
/// The recorded-call assertion is the foundation of Phase 2 (SDK transport probe)
/// and Phase 8 (two-user concurrency proof).
///
/// Recording approach: WireMock.Net 1.6.7 exposes
/// <c>IBodyResponseBuilder.WithBodyAsJson(Func&lt;IRequestMessage, object&gt;)</c>
/// which is evaluated at request-serve time. This lets us capture
/// <c>IRequestMessage.Headers</c> and <c>IRequestMessage.Body</c> inside the
/// factory, record the call, and return the serialisable response object — all
/// in one step, with no manual ResponseMessage construction required.
/// </summary>
public sealed class FakeDownstreamMcp : IAsyncDisposable
{
    private readonly WireMockServer _server;

    public string Url => _server.Url!;

    /// <summary>
    /// Every HTTP request received by the fixture, in arrival order.
    /// Returns a snapshot taken under the recording lock — safe to read from
    /// any thread, including while concurrent requests are still arriving.
    /// </summary>
    public IReadOnlyList<RecordedCall> RecordedCalls
    {
        get
        {
            lock (_recordLock)
            {
                return _recorded.ToArray();
            }
        }
    }
    private readonly List<RecordedCall> _recorded = new();
    private readonly object _recordLock = new();

    private readonly List<FakeTool> _tools = new()
    {
        new FakeTool(
            Name: "ping",
            Description: "Returns pong.",
            InputSchema: """{"type":"object","properties":{},"required":[]}"""),
    };
    private readonly object _toolsLock = new();

    /// <summary>Snapshot of the currently advertised tool catalog.</summary>
    public IReadOnlyList<FakeTool> Tools
    {
        get { lock (_toolsLock) { return _tools.ToArray(); } }
    }

    public void SetTools(params FakeTool[] tools)
    {
        lock (_toolsLock)
        {
            _tools.Clear();
            _tools.AddRange(tools);
        }
    }

    public void ClearTools()
    {
        lock (_toolsLock) { _tools.Clear(); }
    }

    public void AddTool(FakeTool tool)
    {
        lock (_toolsLock) { _tools.Add(tool); }
    }

    public FakeDownstreamMcp()
    {
        _server = WireMockServer.Start();
        SetupJsonRpc();
    }

    private void SetupJsonRpc()
    {
        // Each mapping uses WithBodyAsJson(Func<IRequestMessage, object>) so that
        // the factory executes at request-serve time. We record inside the factory
        // and return the serialisable response object. Method strings match by
        // body substring — pragmatic and sufficient for inputs we control.

        // initialize
        _server.Given(Request.Create()
                .UsingPost()
                .WithBody((string? b) => b != null && b.Contains("\"initialize\"")))
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(req =>
                {
                    Record(req, "initialize");
                    return new
                    {
                        jsonrpc = "2.0",
                        id      = TryExtractId(req.Body),
                        result  = new
                        {
                            protocolVersion = "2024-11-05",
                            capabilities    = new { tools = new { } },
                            serverInfo      = new { name = "fake-downstream", version = "0.0.1" },
                        },
                    };
                }));

        // tools/list — reads Tools at serve time so reconfiguration is reflected
        _server.Given(Request.Create()
                .UsingPost()
                .WithBody((string? b) => b != null && b.Contains("\"tools/list\"")))
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(req =>
                {
                    Record(req, "tools/list");
                    FakeTool[] toolsSnapshot;
                    lock (_toolsLock) { toolsSnapshot = _tools.ToArray(); }
                    return new
                    {
                        jsonrpc = "2.0",
                        id      = TryExtractId(req.Body),
                        result  = new { tools = toolsSnapshot },
                    };
                }));

        // tools/call
        _server.Given(Request.Create()
                .UsingPost()
                .WithBody((string? b) => b != null && b.Contains("\"tools/call\"")))
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(req =>
                {
                    Record(req, "tools/call");
                    return new
                    {
                        jsonrpc = "2.0",
                        id      = TryExtractId(req.Body),
                        result  = new
                        {
                            content = new[] { new { type = "text", text = "pong" } },
                            isError = false,
                        },
                    };
                }));
    }

    private void Record(WireMock.IRequestMessage req, string method)
    {
        string? auth = null;
        if (req.Headers is not null &&
            req.Headers.TryGetValue("Authorization", out var vals) &&
            vals.Count > 0)
        {
            auth = vals[0];
        }

        lock (_recordLock)
        {
            _recorded.Add(new RecordedCall(
                Method:        method,
                Authorization: auth,
                RawBody:       req.Body));
        }
    }

    private static string? TryExtractId(string? body)
    {
        if (string.IsNullOrEmpty(body)) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("id", out var idEl))
            {
                return idEl.ValueKind switch
                {
                    System.Text.Json.JsonValueKind.Number => idEl.GetRawText(),
                    System.Text.Json.JsonValueKind.String => idEl.GetString(),
                    _                                     => null,
                };
            }
        }
        catch (System.Text.Json.JsonException) { /* ignore */ }
        return null;
    }

    public ValueTask DisposeAsync()
    {
        _server.Stop();
        _server.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>Tool descriptor used by the fake's tools/list response.</summary>
public sealed record FakeTool(string Name, string Description, string InputSchema);

/// <summary>One request observed by the fake, in arrival order.</summary>
public sealed record RecordedCall(string Method, string? Authorization, string? RawBody);
