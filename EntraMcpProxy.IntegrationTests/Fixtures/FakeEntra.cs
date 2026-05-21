using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

/// <summary>
/// In-memory fake Entra ID (Azure AD) v2.0 endpoints, served via WireMock.Net.
///
/// Provides:
///   - GET  /{tenantId}/v2.0/.well-known/openid-configuration   — OIDC discovery
///   - GET  /{tenantId}/discovery/v2.0/keys                     — JWKS (public key)
///   - POST /{tenantId}/oauth2/v2.0/token                       — stub token endpoint
///
/// Use <see cref="IssueUserToken"/> to mint RSA-signed access tokens whose signature
/// can be validated by EntraMcpProxy against this fixture's JWKS.
///
/// Default audience is "api://test-client-id" — override via the constructor for tests
/// that need a different audience claim.
/// </summary>
public sealed class FakeEntra : IAsyncDisposable
{
    private readonly WireMockServer _server;
    private readonly RSA _rsa;

    public string Url => _server.Url!;
    public string TenantId { get; }
    public string Audience { get; }
    public string Issuer => $"{Url}/{TenantId}/v2.0";
    public RsaSecurityKey SigningKey { get; }

    public FakeEntra(string tenantId, string audience = "api://test-client-id")
    {
        TenantId = tenantId;
        Audience = audience;

        _rsa = RSA.Create(2048);
        SigningKey = new RsaSecurityKey(_rsa) { KeyId = "fake-entra-key-1" };

        _server = WireMockServer.Start();
        SetupOpenIdConfiguration();
        SetupJwks();
        SetupTokenEndpoint();
    }

    /// <summary>
    /// Mint an RSA-signed JWT in the same shape as an Entra v2.0 access token for
    /// the configured tenant and audience. Required claims: oid, tid, aud, iss, scp.
    /// </summary>
    public string IssueUserToken(string oid, string scope = "user_impersonation",
        DateTime? expires = null)
    {
        DateTime exp = expires ?? DateTime.UtcNow.AddMinutes(30);

        Claim[] claims =
        {
            new("oid", oid),
            new("tid", TenantId),
            new("scp", scope),
        };

        var token = new JwtSecurityToken(
            issuer:    Issuer,
            audience:  Audience,
            claims:    claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires:   exp,
            signingCredentials: new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private void SetupOpenIdConfiguration()
    {
        var config = new
        {
            issuer                                = Issuer,
            jwks_uri                              = $"{Url}/{TenantId}/discovery/v2.0/keys",
            authorization_endpoint                = $"{Url}/{TenantId}/oauth2/v2.0/authorize",
            token_endpoint                        = $"{Url}/{TenantId}/oauth2/v2.0/token",
            id_token_signing_alg_values_supported = new[] { "RS256" },
            response_types_supported              = new[] { "code" },
            subject_types_supported               = new[] { "pairwise" },
            scopes_supported                      = new[] { "openid", "profile", "offline_access" },
        };

        _server
            .Given(Request.Create()
                .WithPath($"/{TenantId}/v2.0/.well-known/openid-configuration")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(config));
    }

    private void SetupJwks()
    {
        RSAParameters p = _rsa.ExportParameters(false);
        var jwks = new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = SigningKey.KeyId,
                    alg = "RS256",
                    n   = Base64UrlEncoder.Encode(p.Modulus!),
                    e   = Base64UrlEncoder.Encode(p.Exponent!),
                },
            },
        };

        _server
            .Given(Request.Create()
                .WithPath($"/{TenantId}/discovery/v2.0/keys")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(jwks));
    }

    private void SetupTokenEndpoint()
    {
        // Default: return a deterministic stub access_token. Individual tests can
        // override by reconfiguring the server with a higher-priority mapping.
        _server
            .Given(Request.Create()
                .WithPath($"/{TenantId}/oauth2/v2.0/token")
                .UsingPost())
            .RespondWith(Response.Create()
                .WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithBodyAsJson(new
                {
                    access_token = "stub-downstream-token",
                    token_type   = "Bearer",
                    expires_in   = 3600,
                }));
    }

    public ValueTask DisposeAsync()
    {
        _server.Stop();
        _server.Dispose();
        _rsa.Dispose();
        return ValueTask.CompletedTask;
    }
}
