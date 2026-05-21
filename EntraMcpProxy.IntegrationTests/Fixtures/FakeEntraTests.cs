using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

public class FakeEntraTests
{
    [Fact]
    public async Task Serves_openid_configuration()
    {
        await using var entra = new FakeEntra(Guid.NewGuid().ToString());
        using var http = new HttpClient();

        HttpResponseMessage resp = await http.GetAsync(
            $"{entra.Url}/{entra.TenantId}/v2.0/.well-known/openid-configuration");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        JsonElement body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("issuer").GetString().Should().Be(entra.Issuer);
        body.GetProperty("jwks_uri").GetString().Should().Contain("/discovery/v2.0/keys");
    }

    [Fact]
    public async Task Serves_jwks_with_public_key()
    {
        await using var entra = new FakeEntra(Guid.NewGuid().ToString());
        using var http = new HttpClient();

        HttpResponseMessage resp = await http.GetAsync(
            $"{entra.Url}/{entra.TenantId}/discovery/v2.0/keys");

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        JsonElement body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("keys").GetArrayLength().Should().Be(1);
        JsonElement key = body.GetProperty("keys")[0];
        key.GetProperty("kty").GetString().Should().Be("RSA");
        key.GetProperty("kid").GetString().Should().Be(entra.SigningKey.KeyId);
    }

    [Fact]
    public async Task Token_endpoint_returns_stub()
    {
        await using var entra = new FakeEntra(Guid.NewGuid().ToString());
        using var http = new HttpClient();

        HttpResponseMessage resp = await http.PostAsync(
            $"{entra.Url}/{entra.TenantId}/oauth2/v2.0/token",
            new StringContent("grant_type=client_credentials", System.Text.Encoding.UTF8,
                "application/x-www-form-urlencoded"));

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        JsonElement body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("access_token").GetString().Should().Be("stub-downstream-token");
    }

    [Fact]
    public void Issued_token_validates_against_fixture_signing_key()
    {
        using var entra = ActOnDispose(new FakeEntra(Guid.NewGuid().ToString()));
        string token = entra.Inner.IssueUserToken(oid: "test-user-oid");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = entra.Inner.Issuer,
            ValidateAudience         = true,
            ValidAudience            = entra.Inner.Audience,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = entra.Inner.SigningKey,
            ClockSkew                = TimeSpan.FromMinutes(1),
        };

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(token, validationParameters, out _);

        principal.FindFirst("oid")!.Value.Should().Be("test-user-oid");
        principal.FindFirst("tid")!.Value.Should().Be(entra.Inner.TenantId);
        principal.FindFirst("scp")!.Value.Should().Be("user_impersonation");
    }

    // Small synchronous-disposal helper since FakeEntra is IAsyncDisposable
    // and this test is synchronous.
    private static AsyncDisposalAdapter<T> ActOnDispose<T>(T inner) where T : IAsyncDisposable
        => new(inner);

    private sealed class AsyncDisposalAdapter<T>(T inner) : IDisposable where T : IAsyncDisposable
    {
        public T Inner { get; } = inner;
        public void Dispose() => Inner.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
