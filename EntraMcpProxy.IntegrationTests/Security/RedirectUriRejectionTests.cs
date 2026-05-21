using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding H3: /authorize must not forward arbitrary redirect_uri to Entra.
/// The proxy enforces an exact-match allowlist via IRedirectUriValidator.
///
/// ProxyAppFactory configures AllowedRedirectUris = ["https://claude.ai/api/mcp/auth_callback"].
/// </summary>
public class RedirectUriRejectionTests
{
    private const string AllowedRedirect = "https://claude.ai/api/mcp/auth_callback";

    [Fact]
    public async Task Authorize_with_allowed_redirect_uri_redirects_to_entra()
    {
        // Need a non-redirecting client so we can inspect the 302 itself.
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await http.GetAsync(
            $"/authorize?response_type=code" +
            $"&redirect_uri={System.Uri.EscapeDataString(AllowedRedirect)}" +
            $"&state=abc" +
            $"&code_challenge=challenge" +
            $"&code_challenge_method=S256");

        // 302 Redirect to Entra; the Location header should target login.microsoftonline.com
        resp.StatusCode.Should().Be(HttpStatusCode.Redirect);
        resp.Headers.Location!.Host.Should().Be("login.microsoftonline.com");
    }

    [Fact]
    public async Task Authorize_with_unlisted_redirect_uri_returns_400()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await http.GetAsync(
            "/authorize?response_type=code" +
            "&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb" +
            "&state=abc&code_challenge=c&code_challenge_method=S256");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        // Must NOT have redirected — the Location header should be unset.
        resp.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task Authorize_with_missing_redirect_uri_returns_400()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await http.GetAsync("/authorize?response_type=code&state=abc&code_challenge=c&code_challenge_method=S256");
        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_with_http_redirect_uri_returns_400()
    {
        // Even if an http URI somehow appeared in the request, the validator's
        // mandatory-https rule rejects it.
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var resp = await http.GetAsync(
            "/authorize?response_type=code" +
            "&redirect_uri=http%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback" +
            "&state=abc&code_challenge=c&code_challenge_method=S256");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
