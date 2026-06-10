using System.Collections.Concurrent;
using System.Net.Http.Headers;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

public class McpStatelessTransportTests
{
    [Fact(Timeout = 30_000)]
    public async Task Mcp_transport_does_not_issue_or_require_server_side_session_ids()
    {
        var tenantId = Guid.NewGuid().ToString();
        var clientId = Guid.NewGuid().ToString();

        await using var entra = new FakeEntra(tenantId, audience: clientId);
        await using var factory = new ProxyAppFactory
        {
            EntraAuthority = entra.Issuer,
            TenantId = tenantId,
            ClientId = clientId,
        };

        var token = entra.IssueUserToken(oid: "alice-oid");
        var recorder = new McpHeaderRecorder(token, factory.Server.CreateHandler());
        using var http = new HttpClient(recorder)
        {
            BaseAddress = factory.Server.BaseAddress,
        };

        await using var client = await McpClient.CreateAsync(
            new HttpClientTransport(
                new HttpClientTransportOptions { Endpoint = factory.Server.BaseAddress },
                http,
                loggerFactory: null,
                ownsHttpClient: false),
            new McpClientOptions
            {
                ClientInfo = new Implementation { Name = "stateless-test-client", Version = "0.0.1" },
            });

        var tools = await client.ListToolsAsync();

        tools.Should().BeEmpty("the default integration-test factory configures no downstream tools");
        recorder.ResponseSessionIds.Should().AllSatisfy(value => value.Should().BeNullOrEmpty());
        recorder.RequestSessionIds.Should().AllSatisfy(value => value.Should().BeNullOrEmpty());
    }

    [Fact(Timeout = 30_000)]
    public async Task Mcp_transport_accepts_configured_mcp_path()
    {
        var tenantId = Guid.NewGuid().ToString();
        var clientId = Guid.NewGuid().ToString();

        await using var entra = new FakeEntra(tenantId, audience: clientId);
        await using var factory = new ProxyAppFactory
        {
            EntraAuthority = entra.Issuer,
            TenantId = tenantId,
            ClientId = clientId,
        };

        var token = entra.IssueUserToken(oid: "alice-oid");
        using var http = new HttpClient(new FixedBearerHandler(token, factory.Server.CreateHandler()))
        {
            BaseAddress = factory.Server.BaseAddress,
        };
        var mcpEndpoint = new Uri(factory.Server.BaseAddress!, "mcp");

        await using var client = await McpClient.CreateAsync(
            new HttpClientTransport(
                new HttpClientTransportOptions { Endpoint = mcpEndpoint },
                http,
                loggerFactory: null,
                ownsHttpClient: false),
            new McpClientOptions
            {
                ClientInfo = new Implementation { Name = "mcp-path-test-client", Version = "0.0.1" },
            });

        var tools = await client.ListToolsAsync();

        tools.Should().BeEmpty("the default integration-test factory configures no downstream tools");
    }

    private sealed class McpHeaderRecorder : DelegatingHandler
    {
        private readonly string _bearerToken;

        public ConcurrentQueue<string?> RequestSessionIds { get; } = new();
        public ConcurrentQueue<string?> ResponseSessionIds { get; } = new();

        public McpHeaderRecorder(string bearerToken, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            _bearerToken = bearerToken;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestSessionIds.Enqueue(
                request.Headers.TryGetValues("MCP-Session-Id", out var requestValues)
                    ? requestValues.FirstOrDefault()
                    : null);

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _bearerToken);

            var response = await base.SendAsync(request, cancellationToken);

            ResponseSessionIds.Enqueue(
                response.Headers.TryGetValues("MCP-Session-Id", out var responseValues)
                    ? responseValues.FirstOrDefault()
                    : null);

            return response;
        }
    }

    private sealed class FixedBearerHandler : DelegatingHandler
    {
        private readonly string _bearerToken;

        public FixedBearerHandler(string bearerToken, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            _bearerToken = bearerToken;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _bearerToken);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
