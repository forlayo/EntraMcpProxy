using System;
using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Auth;

/// <summary>
/// Validates the OAuth <c>redirect_uri</c> parameter at the proxy's
/// /authorize endpoint. Closes audit finding H3: without this check
/// the proxy is an open redirect — any caller with the proxy URL can
/// trigger an Entra flow that lands on their own URL.
///
/// Rules (RFC 6749 §3.1.2 compliant):
/// <list type="bullet">
///   <item>Match against <see cref="ProxyOptions.AllowedRedirectUris"/> by
///         <em>exact</em> ordinal comparison — no prefix/suffix matching.</item>
///   <item>Scheme MUST be <c>https</c>, regardless of allowlist contents
///         (defense-in-depth against an over-permissive allowlist).</item>
///   <item>Empty / whitespace / null input is rejected.</item>
/// </list>
/// </summary>
public interface IRedirectUriValidator
{
    bool IsAllowed(string? candidate);
}

/// <inheritdoc cref="IRedirectUriValidator"/>
public sealed class RedirectUriValidator : IRedirectUriValidator
{
    private readonly IOptions<ProxyOptions> _options;

    public RedirectUriValidator(IOptions<ProxyOptions> options)
    {
        _options = options;
    }

    public bool IsAllowed(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        // Scheme must be https — independent of allowlist contents.
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        // Exact ordinal match against any allowlisted entry.
        foreach (var allowed in _options.Value.AllowedRedirectUris)
        {
            if (string.Equals(candidate, allowed, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
