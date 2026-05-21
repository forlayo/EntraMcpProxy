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
/// Audit finding H5 (defense-in-depth): the proxy must NOT trust
/// X-Forwarded-* headers from arbitrary sources.
///
/// Task 4.2 already proved the discovery URLs ignore X-Forwarded-Host
/// for URL CONSTRUCTION. This test class pins down the related invariant
/// that the X-Forwarded-Proto header does not cause the proxy to advertise
/// http:// anywhere in the OAuth metadata, regardless of where in Program.cs
/// the discovery URL is composed.
/// </summary>
public class ForwardedHeadersDisabledTests
{
    [Fact]
    public async Task OpenidConfiguration_does_not_emit_http_when_XForwardedProto_is_spoofed()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        req.Headers.Add("X-Forwarded-Proto", "http");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        string body = await resp.Content.ReadAsStringAsync();
        body.Should().NotContain("http://");
        body.Should().NotContain("evil.example.com");
        // Sanity: the configured https URL IS present.
        body.Should().Contain("https://proxy.test");
    }

    [Fact]
    public async Task OauthProtectedResource_does_not_emit_http_when_XForwardedProto_is_spoofed()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-protected-resource");
        req.Headers.Add("X-Forwarded-Proto", "http");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        string body = await resp.Content.ReadAsStringAsync();
        body.Should().NotContain("http://");
        body.Should().NotContain("evil.example.com");
        body.Should().Contain("https://proxy.test");
    }

    [Fact]
    public async Task WwwAuthenticate_does_not_emit_http_when_XForwardedProto_is_spoofed()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        req.Headers.Add("X-Forwarded-Proto", "http");
        req.Headers.Add("X-Forwarded-Host",  "evil.example.com");
        req.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        var resp = await client.SendAsync(req);

        resp.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        string wwwAuth = resp.Headers.WwwAuthenticate.ToString();
        wwwAuth.Should().NotContain("http://");
        wwwAuth.Should().NotContain("evil.example.com");
        wwwAuth.Should().Contain("https://proxy.test");
    }
}
