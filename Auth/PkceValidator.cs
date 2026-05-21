using System;
using System.Text.RegularExpressions;

namespace EntraMcpProxy.Auth;

/// <summary>
/// Validates the OAuth 2.0 PKCE parameters (<c>code_challenge</c> and
/// <c>code_challenge_method</c>) on incoming /authorize requests.
///
/// Closes audit finding H4: the proxy advertises
/// <c>code_challenge_methods_supported: ["S256"]</c> in its discovery
/// document but had no server-side enforcement. A malicious or
/// misbehaving client could skip PKCE and rely on Entra alone for
/// enforcement — fragile. This validator provides defense in depth.
///
/// Rules (RFC 7636):
/// <list type="bullet">
///   <item><c>code_challenge</c> required, non-empty, base64url charset,
///         43 to 128 characters in length (§4.2).</item>
///   <item><c>code_challenge_method</c> required, exactly <c>S256</c> —
///         case-sensitive per §4.3.</item>
/// </list>
/// </summary>
public sealed class PkceValidator
{
    private static readonly Regex Base64UrlCharset =
        new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);

    public PkceValidationResult Validate(string? challenge, string? method)
    {
        if (string.IsNullOrWhiteSpace(challenge))
        {
            return PkceValidationResult.Fail("code_challenge is required.");
        }

        if (challenge.Length is < 43 or > 128)
        {
            return PkceValidationResult.Fail("code_challenge length must be 43..128 characters.");
        }

        if (!Base64UrlCharset.IsMatch(challenge))
        {
            return PkceValidationResult.Fail("code_challenge must use the base64url character set (A-Z, a-z, 0-9, '-', '_').");
        }

        if (method is null)
        {
            return PkceValidationResult.Fail("code_challenge_method is required.");
        }

        if (!string.Equals(method, "S256", StringComparison.Ordinal))
        {
            // Covers empty string, whitespace, "plain", "s256", etc.
            return PkceValidationResult.Fail("code_challenge_method must be exactly 'S256'.");
        }

        return PkceValidationResult.Success;
    }
}

public readonly record struct PkceValidationResult(bool IsValid, string? Error)
{
    public static readonly PkceValidationResult Success = new(true, null);
    public static PkceValidationResult Fail(string error) => new(false, error);
}
