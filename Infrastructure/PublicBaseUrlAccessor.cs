using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Returns the proxy's canonical public base URL, sourced from
/// <see cref="ProxyOptions.PublicBaseUrl"/>. Never reads request headers.
///
/// This is the H5 lockdown: discovery, protected-resource metadata, and
/// WWW-Authenticate headers all derive from this single source so an
/// attacker cannot manipulate them via X-Forwarded-Host / X-Forwarded-Proto.
/// </summary>
public interface IPublicBaseUrlAccessor
{
    string Get();
}

/// <inheritdoc cref="IPublicBaseUrlAccessor"/>
public sealed class PublicBaseUrlAccessor : IPublicBaseUrlAccessor
{
    private readonly IOptions<ProxyOptions> _options;

    public PublicBaseUrlAccessor(IOptions<ProxyOptions> options)
    {
        _options = options;
    }

    public string Get() => _options.Value.PublicBaseUrl.TrimEnd('/');
}
