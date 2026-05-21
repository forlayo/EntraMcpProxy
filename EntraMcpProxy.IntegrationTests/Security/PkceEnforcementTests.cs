using System.Net;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding H4: /authorize must enforce PKCE with code_challenge_method=S256.
/// The proxy's discovery document advertises S256 as the only supported method;
/// this test suite verifies that the proxy itself enforces this rather than
/// delegating enforcement entirely to Entra.
///
/// ProxyAppFactory configures AllowedRedirectUris = ["https://claude.ai/api/mcp/auth_callback"].
/// </summary>
public class PkceEnforcementTests
{
    private const string AllowedRedirect = "https://claude.ai/api/mcp/auth_callback";

    private static WebApplicationFactoryClientOptions NoRedirect() =>
        new() { AllowAutoRedirect = false };

    // 43-char base64url string (valid lower bound per RFC 7636 §4.2)
    private const string ValidChallenge = "abcd1234ABCD-_56abcd1234ABCD-_56abcd1234ABC";

    [Fact]
    public async Task Authorize_without_code_challenge_returns_400()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(NoRedirect());
        var resp = await http.GetAsync(
            $"/authorize?response_type=code" +
            $"&redirect_uri={System.Uri.EscapeDataString(AllowedRedirect)}" +
            $"&state=abc");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_with_plain_method_returns_400()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(NoRedirect());
        var resp = await http.GetAsync(
            $"/authorize?response_type=code" +
            $"&redirect_uri={System.Uri.EscapeDataString(AllowedRedirect)}" +
            $"&state=abc&code_challenge={ValidChallenge}&code_challenge_method=plain");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_with_short_challenge_returns_400()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(NoRedirect());
        var shortChallenge = new string('A', 42);
        var resp = await http.GetAsync(
            $"/authorize?response_type=code" +
            $"&redirect_uri={System.Uri.EscapeDataString(AllowedRedirect)}" +
            $"&state=abc&code_challenge={shortChallenge}&code_challenge_method=S256");

        resp.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_with_valid_PKCE_redirects_to_entra()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient(NoRedirect());
        var resp = await http.GetAsync(
            $"/authorize?response_type=code" +
            $"&redirect_uri={System.Uri.EscapeDataString(AllowedRedirect)}" +
            $"&state=abc&code_challenge={ValidChallenge}&code_challenge_method=S256");

        resp.StatusCode.Should().Be(HttpStatusCode.Redirect);
        resp.Headers.Location!.Host.Should().Be("login.microsoftonline.com");
    }
}
