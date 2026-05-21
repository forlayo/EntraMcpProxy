using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding H5: the proxy must NOT trust X-Forwarded-Host /
/// X-Forwarded-Proto headers when constructing OAuth metadata URLs.
/// </summary>
public class ForwardedHostSpoofTests
{
    private const string ConfiguredBase = "https://proxy.test";

    [Fact]
    public async Task OpenidConfiguration_ignores_XForwardedHost()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        req.Headers.Add("X-Forwarded-Proto", "http");

        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("issuer").GetString().Should().Be(ConfiguredBase);
        body.GetProperty("authorization_endpoint").GetString().Should().StartWith(ConfiguredBase);
        body.GetProperty("token_endpoint").GetString().Should().StartWith(ConfiguredBase);
        body.GetRawText().Should().NotContain("evil.example.com");
        body.GetRawText().Should().NotContain("http://");  // configured base is https
    }

    [Fact]
    public async Task OauthProtectedResource_ignores_XForwardedHost()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-protected-resource");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        req.Headers.Add("X-Forwarded-Proto", "http");

        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var ass = body.GetProperty("authorization_servers");
        ass.GetArrayLength().Should().Be(1);
        ass[0].GetString().Should().Be(ConfiguredBase);
        body.GetRawText().Should().NotContain("evil.example.com");
    }

    [Fact]
    public async Task WwwAuthenticate_resource_metadata_ignores_XForwardedHost()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();
        // Hit a protected MCP route with no bearer — should get 401 with WWW-Authenticate
        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        req.Headers.Add("X-Forwarded-Proto", "http");
        req.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var wwwAuth = resp.Headers.WwwAuthenticate.ToString();
        wwwAuth.Should().Contain(ConfiguredBase);
        wwwAuth.Should().NotContain("evil.example.com");
        wwwAuth.Should().Contain("/.well-known/oauth-protected-resource");
    }
}
