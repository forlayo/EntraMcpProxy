using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.E2ETests.Fixtures;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.E2ETests;

/// <summary>
/// End-to-end happy path through the real proxy container against
/// WireMock-Entra and WireMock-downstream. Verifies the deployment
/// configuration (Dockerfile, env-var binding, Docker networking)
/// actually wires together correctly.
///
/// Other security behaviors (redirect_uri rejection, PKCE enforcement,
/// rate limiting, two-user concurrency, etc.) are covered by the
/// integration test suite — those exercise the same code paths in
/// process. This E2E adds the deployment-shape proof.
///
/// What is proven here:
///   1. The proxy container boots, resolves WireMock-Entra for OIDC
///      discovery and JWKS, and validates a user JWT.
///   2. The proxy performs an OBO exchange against WireMock-Entra
///      and obtains a downstream access token.
///   3. The downstream receives the OBO token (not the user's raw JWT).
///   4. The proxy returns a Phase-10 provenance-wrapped result.
/// </summary>
[Collection("E2E")]
public class HappyPathTests
{
    private const string TenantId = ProxyContainerFixture.FakeTenantId;
    private const string ClientId = ProxyContainerFixture.FakeClientId;
    private static readonly TimeSpan McpOperationTimeout = TimeSpan.FromSeconds(20);

    private readonly ProxyContainerFixture _fx;

    public HappyPathTests(ProxyContainerFixture fx)
    {
        _fx = fx;
    }

    [Fact(Timeout = 180_000)]
    public async Task User_token_flows_through_OBO_exchange_to_downstream()
    {
        // 1. Generate the RSA keypair the test will use to sign user tokens.
        //    The public half is published via the JWKS stub so the proxy can
        //    validate the user token signature.
        using var rsa = RSA.Create(2048);
        var signingKey = new RsaSecurityKey(rsa) { KeyId = "e2e-test-key-1" };

        // 2. Layer WireMock-Entra mappings (OIDC discovery, JWKS, token endpoint).
        //    These must be in place BEFORE the first authenticated request reaches
        //    the proxy, because JwtBearerHandler fetches the OIDC config lazily on
        //    first use.
        await ConfigureFakeEntraAsync(_fx.EntraAdminUrl, rsa, signingKey.KeyId);

        // 3. Mint a user JWT signed with the RSA key whose public half was just published.
        var userToken = MintUserToken(signingKey, oid: "alice-e2e");

        // 4. Wait for the proxy to have registered the "fake__ping" tool so it can
        //    be called. The tool is discovered at startup, but we wait explicitly
        //    to avoid a race where the first call arrives before discovery completes.
        await WaitForToolAsync(_fx, userToken, toolName: "fake__ping", timeoutMs: 30_000);

        // 5. Call tools/call via the MCP SDK client (handles MCP session lifecycle
        //    including initialize + tools/call).
        var result = await CallFakePingAsync(_fx, userToken);

        // 6. Phase-10 provenance wrapping: tool result text is wrapped in
        //    <downstream-content source="{prefix}" tool="{toolName}">
        result.Should().NotBeEmpty("tools/call must return at least one content block");
        var textBlock = result[0] as TextContentBlock;
        textBlock.Should().NotBeNull("the content block must be a TextContentBlock");
        var resultText = textBlock!.Text ?? "";

        resultText.Should().Contain("<downstream-content",
            "Phase-10 provenance wrapper must be present in the proxy response");
        resultText.Should().Contain("pong",
            "the downstream tool result 'pong' must appear in the proxy response");

        // 7. Verify the downstream received an OBO-exchanged token, NOT the user's raw JWT.
        var downstreamRequestsJson = await GetWireMockRequestsAsync(_fx.DownstreamAdminUrl);

        downstreamRequestsJson.Should().NotContain(userToken,
            "the user's raw JWT must never reach the downstream; only the OBO-exchanged token should");

        downstreamRequestsJson.Should().Contain("tools/call",
            "the downstream must have received a tools/call request from the proxy");
    }

    // ─── MCP client helpers ───────────────────────────────────────────────────

    /// <summary>
    /// Creates an <see cref="McpClient"/> connected to the proxy container.
    /// The client injects the supplied bearer token on every HTTP request via a
    /// DelegatingHandler, replicating the pattern used in
    /// <c>TwoUserConcurrencyTests.CreateProxyMcpClientAsync</c>.
    /// </summary>
    private static async Task<McpClient> CreateMcpClientAsync(
        ProxyContainerFixture fx, string bearerToken)
    {
        var proxyUri = fx.Http.BaseAddress!;
        var handler = new FixedBearerHandler(bearerToken, new HttpClientHandler());
        var http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = proxyUri,
            Timeout = McpOperationTimeout,
        };

        return await McpClient.CreateAsync(
            new HttpClientTransport(
                new HttpClientTransportOptions { Endpoint = proxyUri },
                http,
                loggerFactory: null,
                ownsHttpClient: true),
            new McpClientOptions
            {
                ClientInfo = new Implementation { Name = "e2e-test-client", Version = "0.0.0" },
            }).WaitAsync(McpOperationTimeout);
    }

    /// <summary>
    /// Polls the proxy's tool list (via the MCP client) until "fake__ping" appears
    /// or the timeout expires. The tool is registered by ToolAggregatorService at
    /// startup; this wait handles the race between container boot and first test call.
    /// </summary>
    private static async Task WaitForToolAsync(
        ProxyContainerFixture fx, string bearerToken,
        string toolName, int timeoutMs)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        Exception? lastEx = null;
        string lastToolList = "(none)";

        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var client = await CreateMcpClientAsync(fx, bearerToken);
                try
                {
                    using var cts = new CancellationTokenSource(McpOperationTimeout);
                    var tools = await client.ListToolsAsync(options: null, cancellationToken: cts.Token);
                    lastToolList = string.Join(", ", tools.Select(t => t.Name));
                    if (tools.Any(t => t.Name == toolName)) return;
                }
                finally
                {
                    await DisposeClientAsync(client);
                }
            }
            catch (Exception ex)
            {
                lastEx = ex;
            }
            await Task.Delay(500);
        }

        // Fetch WireMock downstream requests to diagnose what happened
        string downstreamLog = "(unavailable)";
        try
        {
            downstreamLog = await GetWireMockRequestsAsync(fx.DownstreamAdminUrl);
            // Truncate for readability
            if (downstreamLog.Length > 5000) downstreamLog = downstreamLog[..5000] + "...";
        }
        catch { /* best effort */ }

        throw new TimeoutException(
            $"Timed out ({timeoutMs}ms) waiting for tool '{toolName}' to appear in " +
            $"the proxy's tool registry. Last error: {lastEx?.Message ?? "none"}. " +
            $"Last tool list: [{lastToolList}]. " +
            $"WireMock downstream requests: {downstreamLog}");
    }

    private static async Task<IList<ContentBlock>> CallFakePingAsync(
        ProxyContainerFixture fx, string bearerToken)
    {
        var client = await CreateMcpClientAsync(fx, bearerToken);
        try
        {
            using var cts = new CancellationTokenSource(McpOperationTimeout);
            var result = await client.CallToolAsync(
                new CallToolRequestParams { Name = "fake__ping", Arguments = null },
                cancellationToken: cts.Token);
            return result.Content;
        }
        finally
        {
            await DisposeClientAsync(client);
        }
    }

    private static async Task DisposeClientAsync(McpClient client)
    {
        try
        {
            await client.DisposeAsync().AsTask().WaitAsync(McpOperationTimeout);
        }
        catch (TimeoutException)
        {
            // Best-effort cleanup only. The SDK sends a session DELETE on dispose;
            // do not let a stalled cleanup request consume the whole E2E test timeout.
        }
    }

    // ─── WireMock-Entra configuration ────────────────────────────────────────

    /// <summary>
    /// Posts OIDC discovery, JWKS, and token-endpoint mappings to WireMock-Entra.
    ///
    /// The OIDC discovery document is served at the path the proxy's JwtBearerHandler
    /// will fetch from the configured Authority:
    ///   GET /{tenantId}/v2.0/.well-known/openid-configuration
    ///
    /// The JWKS endpoint publishes the public half of <paramref name="rsa"/> so
    /// the proxy can validate user JWTs signed with the private half.
    ///
    /// The token endpoint returns a deterministic OBO access token for any POST,
    /// which the test then checks never matches the user's raw JWT.
    /// </summary>
    private static async Task ConfigureFakeEntraAsync(string adminUrl, RSA rsa, string kid)
    {
        using var http = new HttpClient { BaseAddress = new Uri(adminUrl + "/") };

        // OIDC discovery
        var oidc = new
        {
            request = new
            {
                method = "GET",
                url = $"/{TenantId}/v2.0/.well-known/openid-configuration",
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                jsonBody = new
                {
                    // Issuer must match the Authority env var set in ProxyContainerFixture
                    // and must also be in the proxy's ValidIssuers list (Program.cs).
                    issuer = $"http://entra:8080/{TenantId}/v2.0",
                    jwks_uri = $"http://entra:8080/{TenantId}/discovery/v2.0/keys",
                    authorization_endpoint = $"http://entra:8080/{TenantId}/oauth2/v2.0/authorize",
                    token_endpoint = $"http://entra:8080/{TenantId}/oauth2/v2.0/token",
                    response_types_supported = new[] { "code" },
                    id_token_signing_alg_values_supported = new[] { "RS256" },
                },
            },
        };
        await PostMappingAsync(http, oidc);

        // JWKS — publish the public half of the test RSA key
        var p = rsa.ExportParameters(false);
        var jwks = new
        {
            request = new
            {
                method = "GET",
                url = $"/{TenantId}/discovery/v2.0/keys",
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                jsonBody = new
                {
                    keys = new[]
                    {
                        new
                        {
                            kty = "RSA",
                            use = "sig",
                            kid = kid,
                            alg = "RS256",
                            n = Base64UrlEncoder.Encode(p.Modulus!),
                            e = Base64UrlEncoder.Encode(p.Exponent!),
                        },
                    },
                },
            },
        };
        await PostMappingAsync(http, jwks);

        // Token endpoint — return a deterministic OBO access token.
        // The fixture already seeded a low-priority (priority=10) catch-all stub for
        // this path; this mapping posts at default priority (1) which takes precedence,
        // ensuring the test receives the specific "obo-downstream-token-for-alice-e2e"
        // value that can be distinguished from the startup default.
        var token = new
        {
            request = new
            {
                method = "POST",
                url = $"/{TenantId}/oauth2/v2.0/token",
            },
            response = new
            {
                status = 200,
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                jsonBody = new
                {
                    access_token = "obo-downstream-token-for-alice-e2e",
                    token_type = "Bearer",
                    expires_in = 3600,
                },
            },
        };
        await PostMappingAsync(http, token);
    }

    // ─── JWT minting ──────────────────────────────────────────────────────────

    private static string MintUserToken(RsaSecurityKey key, string oid)
    {
        var claims = new[]
        {
            new Claim("oid", oid),
            new Claim("tid", TenantId),
            new Claim("scp", "user_impersonation"),
        };

        // Issuer matches the OIDC discovery document's "issuer" field AND the
        // Authority env var so the proxy's issuer validation passes.
        // Audience matches the proxy's ValidAudiences list: api://{clientId}.
        var token = new JwtSecurityToken(
            issuer: $"http://entra:8080/{TenantId}/v2.0",
            audience: $"api://{ClientId}",
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // ─── WireMock admin helpers ───────────────────────────────────────────────

    private static async Task PostMappingAsync(HttpClient http, object mapping)
    {
        var json = JsonSerializer.Serialize(mapping);
        using var cts = new CancellationTokenSource(McpOperationTimeout);
        using var resp = await http.PostAsync("mappings",
            new StringContent(json, Encoding.UTF8, "application/json"),
            cts.Token);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Fetches the raw WireMock request log from /__admin/requests and returns
    /// the full JSON body as a string. The string is large enough to scan with
    /// Contains() for JWT substrings, method names, and auth header values.
    /// </summary>
    private static async Task<string> GetWireMockRequestsAsync(string adminUrl)
    {
        using var http = new HttpClient { Timeout = McpOperationTimeout };
        using var cts = new CancellationTokenSource(McpOperationTimeout);
        var resp = await http.GetAsync($"{adminUrl}/requests", cts.Token);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(cts.Token);
    }

    // ─── DelegatingHandler that injects a fixed bearer token ─────────────────

    private sealed class FixedBearerHandler : DelegatingHandler
    {
        private readonly string _token;

        public FixedBearerHandler(string token, HttpMessageHandler inner)
            : base(inner)
        {
            _token = token;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            return base.SendAsync(request, cancellationToken);
        }
    }
}
