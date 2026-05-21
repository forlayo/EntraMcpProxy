using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding N14: MapMcp() routes must enforce authentication.
/// Verify a request without a bearer to any plausible MCP path is rejected.
/// </summary>
public class McpRouteAuthTests
{
    [Theory]
    [InlineData("GET",  "/")]
    [InlineData("POST", "/")]
    [InlineData("GET",  "/sse")]
    [InlineData("POST", "/mcp")]
    [InlineData("GET",  "/messages")]
    public async Task Mcp_routes_without_bearer_are_never_200(string method, string path)
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient();

        var req = new HttpRequestMessage(new HttpMethod(method), path);
        if (method == "POST")
        {
            req.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        }
        var resp = await http.SendAsync(req);

        // A real MCP endpoint must NOT serve 200 without auth. Acceptable outcomes:
        //   401 (recognized MCP endpoint, auth missing)
        //   404 (not an MCP endpoint at this path)
        //   405 (path exists but method not allowed)
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK,
            $"{method} {path} must not return 200 OK to an unauthenticated caller");
    }

    [Fact]
    public async Task Mcp_route_returns_401_when_endpoint_path_is_called_without_bearer()
    {
        // The custom auth middleware emits 401 with WWW-Authenticate for unauthenticated
        // requests to anything not in {/api/healthz, /.well-known, /authorize, /token}.
        // Specifically test the path we KNOW routes to MCP (/mcp).
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        var resp = await http.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        resp.Headers.WwwAuthenticate.ToString().Should().Contain("Bearer");
    }
}
