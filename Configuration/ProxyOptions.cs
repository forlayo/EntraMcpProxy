using System;
using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Configuration;

/// <summary>
/// Strongly-typed proxy runtime settings. Bound from the "Proxy"
/// configuration section. Validated at startup by
/// <see cref="ProxyOptionsValidator"/>.
///
/// PublicBaseUrl is REQUIRED and must be https — discovery endpoints
/// and the WWW-Authenticate header derive from it (never from request
/// headers; this closes the X-Forwarded-Host spoof, finding H5).
///
/// AllowedRedirectUris is the OAuth /authorize allowlist (finding H3).
///
/// EgressAllowlist enumerates the host names downstream MCP servers
/// may be configured against. Cross-checked at startup against each
/// DownstreamServers[*].BaseUrl host (finding N19).
///
/// AllowedOrigins is the MCP spec MUST — DNS rebinding defense. Applied
/// to MCP routes. Empty list = permissive (matches pre-Block-A behavior).
///
/// LogOAuthRequests enables first-integration observability logging on
/// /authorize and /token. Off by default; token values are never logged.
/// </summary>
public sealed record ProxyOptions
{
    public string PublicBaseUrl { get; init; } = "";

    public List<string> AllowedRedirectUris { get; init; } = new();
    public List<string> EgressAllowlist     { get; init; } = new();
    public List<string> AllowedCorsOrigins  { get; init; } = new();

    /// <summary>
    /// MCP spec MUST — Origin header allowlist for DNS rebinding defense.
    /// Applied to MCP routes (not OAuth facade endpoints, which are exempted
    /// because they are server-to-server). When empty, origin check is
    /// permissive — set per the deployment's threat model.
    /// </summary>
    public List<string> AllowedOrigins { get; init; } = new();

    /// <summary>
    /// Diagnostic: log incoming /authorize and /token request shapes
    /// (method, path, headers, form-field NAMES, response status) at
    /// Information level. Designed for first-integration observability —
    /// turn on during initial claude.ai connection, turn off once stable.
    /// Token values, codes, verifiers, and client_secret are NEVER logged.
    /// </summary>
    public bool LogOAuthRequests { get; init; } = false;

    public int RefreshIntervalMinutes { get; init; } = 5;

    public RateLimitOptions          RateLimit      { get; init; } = new();
    public ToolResultOptions         ToolResult     { get; init; } = new();
    public AuthorizationPolicyOptions Authorization { get; init; } = new();

    public sealed record RateLimitOptions
    {
        public int RequestsPerMinute { get; init; } = 30;
    }

    public sealed record ToolResultOptions
    {
        public int MaxBytes { get; init; } = 256 * 1024;

        /// <summary>
        /// Provenance marker style applied to TextContentBlocks in tool results.
        ///
        /// <list type="bullet">
        /// <item><c>Full</c> (default): wrap content in
        /// <c>&lt;downstream-content source=... tool=...&gt;...&lt;/downstream-content&gt;</c>
        /// tags. Strongest provenance signal; visible in claude.ai conversation UI.</item>
        /// <item><c>Inline</c>: prepend a single-line marker
        /// <c>[from {prefix}:{tool}]</c> followed by the content. Less visible in UI;
        /// still gives Claude provenance context. Recommended if Full is too obtrusive.</item>
        /// <item><c>Off</c>: pass content through unchanged. ONLY use when downstream
        /// content is fully trusted (e.g., internal-only MCP servers under your
        /// control). Insecure default for the Azure DevOps integration.</item>
        /// </list>
        /// </summary>
        public ProvenanceStyle Provenance { get; init; } = ProvenanceStyle.Full;
    }
}

/// <summary>
/// Controls how tool result provenance is marked in TextContentBlocks.
/// </summary>
public enum ProvenanceStyle
{
    Full,
    Inline,
    Off,
}

/// <summary>
/// Validates <see cref="ProxyOptions"/> at startup. Aggregates every
/// error into a single failure message so operators see all
/// misconfigurations in one log line.
/// </summary>
public sealed class ProxyOptionsValidator : IValidateOptions<ProxyOptions>
{
    public ValidateOptionsResult Validate(string? name, ProxyOptions o)
    {
        var errors = new List<string>();

        // PublicBaseUrl
        if (string.IsNullOrWhiteSpace(o.PublicBaseUrl))
        {
            errors.Add("Proxy:PublicBaseUrl is required.");
        }
        else if (!Uri.TryCreate(o.PublicBaseUrl, UriKind.Absolute, out var baseUri))
        {
            errors.Add("Proxy:PublicBaseUrl must be an absolute URL.");
        }
        else if (baseUri.Scheme != Uri.UriSchemeHttps)
        {
            errors.Add("Proxy:PublicBaseUrl must use https.");
        }

        // AllowedRedirectUris
        if (o.AllowedRedirectUris.Count == 0)
        {
            errors.Add("Proxy:AllowedRedirectUris must contain at least one entry.");
        }
        else
        {
            foreach (var uri in o.AllowedRedirectUris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var redirect)
                    || redirect.Scheme != Uri.UriSchemeHttps)
                {
                    errors.Add($"Proxy:AllowedRedirectUris entry '{uri}' must be an absolute https URL.");
                }
            }
        }

        // EgressAllowlist (host names only, no scheme / path)
        if (o.EgressAllowlist.Count == 0)
        {
            errors.Add("Proxy:EgressAllowlist must contain at least one host.");
        }
        else
        {
            foreach (var host in o.EgressAllowlist)
            {
                if (string.IsNullOrWhiteSpace(host)
                    || host.Contains('/') || host.Contains(':')
                    || host.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add($"Proxy:EgressAllowlist entry '{host}' must be a bare host name (no scheme or path).");
                }
            }
        }

        // RefreshIntervalMinutes [1..60]
        if (o.RefreshIntervalMinutes < 1 || o.RefreshIntervalMinutes > 60)
        {
            errors.Add($"Proxy:RefreshIntervalMinutes must be in [1..60]; got {o.RefreshIntervalMinutes}.");
        }

        // RateLimit.RequestsPerMinute [1..10000]
        if (o.RateLimit.RequestsPerMinute < 1 || o.RateLimit.RequestsPerMinute > 10_000)
        {
            errors.Add($"Proxy:RateLimit:RequestsPerMinute must be in [1..10000]; got {o.RateLimit.RequestsPerMinute}.");
        }

        // ToolResult.MaxBytes [1..8 MiB]
        if (o.ToolResult.MaxBytes < 1 || o.ToolResult.MaxBytes > 8 * 1024 * 1024)
        {
            errors.Add($"Proxy:ToolResult:MaxBytes must be in [1..{8 * 1024 * 1024}]; got {o.ToolResult.MaxBytes}.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(string.Join("; ", errors));
    }
}
