using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;

namespace EntraMcpProxy.Infrastructure;

internal static class OAuthTokenResponseDiagnostics
{
    public static string Summarize(string json)
    {
        var sb = new StringBuilder("oauth-token-response");

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            AppendPresence(sb, root, "access_token");
            AppendPresence(sb, root, "refresh_token");
            AppendPresence(sb, root, "id_token");
            AppendString(sb, root, "token_type");
            AppendNumber(sb, root, "expires_in");

            if (root.TryGetProperty("access_token", out var accessToken)
                && accessToken.ValueKind == JsonValueKind.String
                && accessToken.GetString() is { Length: > 0 } token)
            {
                AppendAccessTokenClaims(sb, token);
            }
        }
        catch (JsonException ex)
        {
            sb.Append(" parse_error=").Append(ex.GetType().Name);
        }

        return sb.ToString();
    }

    private static void AppendPresence(StringBuilder sb, JsonElement root, string property)
    {
        var present = root.TryGetProperty(property, out var value)
                      && value.ValueKind == JsonValueKind.String
                      && !string.IsNullOrWhiteSpace(value.GetString());
        sb.Append(" has_").Append(property).Append('=').Append(present);
    }

    private static void AppendString(StringBuilder sb, JsonElement root, string property)
    {
        if (root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String)
        {
            sb.Append(' ').Append(property).Append('=').Append(Safe(value.GetString()));
        }
    }

    private static void AppendNumber(StringBuilder sb, JsonElement root, string property)
    {
        if (root.TryGetProperty(property, out var value) && value.TryGetInt64(out var number))
        {
            sb.Append(' ').Append(property).Append('=').Append(number);
        }
    }

    private static void AppendAccessTokenClaims(StringBuilder sb, string token)
    {
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            AppendClaim(sb, "access_token_iss", jwt.Issuer);
            AppendClaim(sb, "access_token_aud", string.Join(",", jwt.Audiences));
            AppendClaim(sb, "access_token_scp", jwt.Claims.FirstOrDefault(c => c.Type == "scp")?.Value);
        }
        catch (ArgumentException ex)
        {
            sb.Append(" access_token_parse_error=").Append(ex.GetType().Name);
        }
    }

    private static void AppendClaim(StringBuilder sb, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            sb.Append(' ').Append(name).Append('=').Append(Safe(value));
        }
    }

    private static string Safe(string? value)
        => (value ?? "").Replace(' ', '|').Replace('\n', '_').Replace('\r', '_');
}
