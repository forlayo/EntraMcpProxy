using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace EntraMcpProxy.LoadTests;

/// <summary>
/// Shared configuration and helpers for all load test scenarios.
/// </summary>
public sealed class LoadTestConfig : IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;

    public string ProxyBaseUrl { get; }
    public string TenantId { get; }
    public string ClientId { get; }
    public string Issuer => $"https://login.microsoftonline.com/{TenantId}/v2.0";

    public LoadTestConfig(string proxyBaseUrl, string tenantId, string clientId)
    {
        ProxyBaseUrl = proxyBaseUrl.TrimEnd('/');
        TenantId = tenantId;
        ClientId = clientId;

        _rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = "load-test-key-1" };
    }

    /// <summary>
    /// Mint a self-signed JWT that looks like an Entra v2.0 access token.
    ///
    /// IMPORTANT: The deployed proxy validates JWTs against the real Entra JWKS.
    /// These synthetic tokens will be REJECTED by a production proxy.
    ///
    /// To use these tokens in load tests, the proxy must be deployed with
    /// ASPNETCORE_ENVIRONMENT=LoadTest and EntraId:RequireHttpsMetadata=false,
    /// OR the proxy's JWT validation must be pointed at a fake Entra that accepts
    /// these keys (e.g., via the EntraId:Authority env var pointing at a WireMock).
    ///
    /// For a real-proxy load test, supply real tokens from a test user's session
    /// by setting LOAD_TEST_BEARER_TOKEN in the environment.
    /// </summary>
    public string MintSyntheticToken(string oid, string scope = "user_impersonation",
        int lifetimeMinutes = 60)
    {
        var claims = new[]
        {
            new Claim("oid", oid),
            new Claim("tid", TenantId),
            new Claim("scp", scope),
        };

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: $"api://{ClientId}",
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(lifetimeMinutes),
            signingCredentials: new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Returns a bearer token for load testing.
    /// Prefers LOAD_TEST_BEARER_TOKEN from the environment (a real token from a
    /// test user session), falling back to a synthetic self-signed token.
    /// </summary>
    public string GetBearerToken(string oid)
    {
        string? realToken = Environment.GetEnvironmentVariable("LOAD_TEST_BEARER_TOKEN");
        return realToken ?? MintSyntheticToken(oid);
    }

    public void Dispose() => _rsa.Dispose();
}
