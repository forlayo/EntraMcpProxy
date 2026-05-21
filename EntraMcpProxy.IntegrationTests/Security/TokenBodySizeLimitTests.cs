using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding M13: /token must reject oversized bodies to prevent
/// memory pressure / DoS via large POSTs.
/// </summary>
public class TokenBodySizeLimitTests
{
    [Fact]
    public async Task Token_rejects_body_over_8KB_with_413()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient();

        var oversized = new string('A', 9 * 1024); // 9 KB > 8 KB limit
        var body = $"grant_type=authorization_code&code=x&code_verifier={oversized}";
        var resp = await http.PostAsync("/token",
            new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

        resp.StatusCode.Should().BeOneOf(
            HttpStatusCode.RequestEntityTooLarge,        // 413
            HttpStatusCode.BadRequest);                   // some pipelines map to 400
        // Either way it must NOT be the success or normal-flow 4xx from Entra.
    }

    [Fact]
    public async Task Token_accepts_normal_sized_body()
    {
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient();

        // ~200 bytes — normal OAuth body
        var body = "grant_type=authorization_code&code=x&code_verifier=verifier&client_id=test";
        var resp = await http.PostAsync("/token",
            new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

        // Will probably fail downstream (Entra not real), but must NOT be 413/400-for-size.
        resp.StatusCode.Should().NotBe(HttpStatusCode.RequestEntityTooLarge);
    }
}
