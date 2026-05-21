using System;
using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Runtime host-suffix allowlist for outbound HTTP requests. Each
/// candidate host is checked against <see cref="ProxyOptions.EgressAllowlist"/>;
/// only matching hosts may receive requests.
///
/// Audit finding N19: the type-level validator (Task 3.3) catches
/// misconfiguration at startup. This service catches everything else
/// — runtime config drift, future code paths that bypass startup
/// validation, etc.
/// </summary>
public sealed class EgressAllowlist
{
    private readonly IOptions<ProxyOptions> _options;
    public EgressAllowlist(IOptions<ProxyOptions> options) => _options = options;

    /// <summary>
    /// Returns true if <paramref name="host"/> is in the configured egress
    /// allowlist. Comparison is ordinal case-insensitive (DNS).
    /// Login.microsoftonline.com is always permitted (the OAuth facade
    /// MUST be able to reach Entra regardless of allowlist contents —
    /// otherwise the proxy can't authenticate users).
    /// </summary>
    public bool IsAllowed(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        // Hard-coded permit for Entra — the proxy cannot function without it.
        if (host.Equals("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase))
            return true;

        var list = _options.Value.EgressAllowlist;
        foreach (var allowed in list)
        {
            if (host.Equals(allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
