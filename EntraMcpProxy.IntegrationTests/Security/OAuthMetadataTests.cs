using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

public class OAuthMetadataTests
{
    [Fact]
    public async Task OpenidConfiguration_advertises_refresh_token_grant()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/.well-known/openid-configuration");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var grants = body.GetProperty("grant_types_supported");
        grants.EnumerateArray()
            .Select(x => x.GetString())
            .Should()
            .Contain(new[] { "authorization_code", "refresh_token" });
    }

    [Fact]
    public async Task OpenidConfiguration_advertises_offline_access_scope()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/.well-known/openid-configuration");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var scopes = body.GetProperty("scopes_supported");
        scopes.EnumerateArray()
            .Select(x => x.GetString())
            .Should()
            .Contain("offline_access");
    }

    [Fact]
    public async Task ProtectedResourceMetadata_advertises_public_base_url_as_resource()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/.well-known/oauth-protected-resource");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("resource").GetString().Should().Be("https://proxy.test");
        body.GetProperty("authorization_servers")
            .EnumerateArray()
            .Select(x => x.GetString())
            .Should()
            .Contain("https://proxy.test");
    }

    [Fact]
    public async Task ProtectedResourceMetadata_path_variant_advertises_matching_mcp_resource()
    {
        await using var factory = new ProxyAppFactory();
        using var client = factory.CreateClient();

        var resp = await client.GetAsync("/.well-known/oauth-protected-resource/mcp");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("resource").GetString().Should().Be("https://proxy.test/mcp");
        body.GetProperty("authorization_servers")
            .EnumerateArray()
            .Select(x => x.GetString())
            .Should()
            .Contain("https://proxy.test");
    }
}
