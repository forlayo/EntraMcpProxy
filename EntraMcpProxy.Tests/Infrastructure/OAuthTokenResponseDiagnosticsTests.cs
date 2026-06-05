using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class OAuthTokenResponseDiagnosticsTests
{
    [Fact]
    public void Summarize_reports_safe_token_shape_without_logging_token_values()
    {
        var accessToken = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            issuer: "https://login.microsoftonline.com/tenant/v2.0",
            audience: "api://client-id",
            claims: new[] { new Claim("scp", "user_impersonation") },
            expires: DateTime.UtcNow.AddMinutes(30)));
        const string refreshToken = "secret-refresh-token";

        var json = $$"""
        {
          "access_token": "{{accessToken}}",
          "refresh_token": "{{refreshToken}}",
          "id_token": "secret-id-token",
          "token_type": "Bearer",
          "expires_in": 3600
        }
        """;

        var summary = OAuthTokenResponseDiagnostics.Summarize(json);

        summary.Should().Contain("has_access_token=True");
        summary.Should().Contain("has_refresh_token=True");
        summary.Should().Contain("has_id_token=True");
        summary.Should().Contain("token_type=Bearer");
        summary.Should().Contain("expires_in=3600");
        summary.Should().Contain("access_token_iss=https://login.microsoftonline.com/tenant/v2.0");
        summary.Should().Contain("access_token_aud=api://client-id");
        summary.Should().Contain("access_token_scp=user_impersonation");
        summary.Should().NotContain(accessToken);
        summary.Should().NotContain(refreshToken);
        summary.Should().NotContain("secret-id-token");
    }
}
