using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Configuration;

/// <summary>
/// Strongly-typed configuration for one downstream MCP server. Bound from
/// each entry of the "DownstreamServers" array. Replaces the legacy
/// DownstreamServerConfig POCO.
///
/// Validated at startup by <see cref="DownstreamServerOptionsValidator"/>.
/// </summary>
public sealed record DownstreamServerOptions
{
    public string Name      { get; init; } = "";
    public string Prefix    { get; init; } = "";
    public string BaseUrl   { get; init; } = "";
    public string AuthType  { get; init; } = "ApiKey";

    public string? ApiKey   { get; init; }

    public EntraIdAuthOptions? EntraId { get; init; }
    public OboOptions?         OBO     { get; init; }

    public bool Enabled        { get; init; } = true;
    public int  TimeoutSeconds { get; init; } = 30;

    public sealed record EntraIdAuthOptions
    {
        public string TenantId     { get; init; } = "";
        public string ClientId     { get; init; } = "";
        public string ClientSecret { get; init; } = "";
        public string Scope        { get; init; } = "";
    }

    public sealed record OboOptions
    {
        public string TenantId     { get; init; } = "";
        public string ClientId     { get; init; } = "";
        public string ClientSecret { get; init; } = "";
        public string TargetScope  { get; init; } = "";
    }
}

/// <summary>
/// Validates the entire DownstreamServers list at startup. Aggregates
/// per-server errors and cross-validates each BaseUrl host against the
/// ProxyOptions.EgressAllowlist (finding N19).
/// </summary>
public sealed class DownstreamServerOptionsValidator
    : IValidateOptions<List<DownstreamServerOptions>>
{
    private static readonly Regex PrefixRegex = new("^[a-z][a-z0-9_]{1,30}$", RegexOptions.Compiled);
    private static readonly string[] KnownAuthTypes = { "OBOToken", "EntraId", "ApiKey" };

    private readonly IOptions<ProxyOptions> _proxy;

    public DownstreamServerOptionsValidator(IOptions<ProxyOptions> proxy)
    {
        _proxy = proxy;
    }

    public ValidateOptionsResult Validate(string? name, List<DownstreamServerOptions> servers)
    {
        var errors = new List<string>();
        var allowlist = new HashSet<string>(_proxy.Value.EgressAllowlist, StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < servers.Count; i++)
        {
            ValidateServer(i, servers[i], allowlist, errors);
        }

        // Duplicate-prefix check
        var duplicates = servers
            .Where(s => !string.IsNullOrEmpty(s.Prefix))
            .GroupBy(s => s.Prefix, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key);
        foreach (var dup in duplicates)
        {
            errors.Add($"DownstreamServers contains duplicate Prefix '{dup}'.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(string.Join("; ", errors));
    }

    private static void ValidateServer(
        int i,
        DownstreamServerOptions s,
        HashSet<string> egressAllowlist,
        List<string> errors)
    {
        string prefix = $"DownstreamServers[{i}]";

        // Prefix
        if (!PrefixRegex.IsMatch(s.Prefix) || s.Prefix.Contains("__"))
        {
            errors.Add($"{prefix}:Prefix '{s.Prefix}' must match ^[a-z][a-z0-9_]{{1,30}}$ and must not contain '__'.");
        }

        // BaseUrl
        if (string.IsNullOrWhiteSpace(s.BaseUrl))
        {
            errors.Add($"{prefix}:BaseUrl is required.");
        }
        else if (!Uri.TryCreate(s.BaseUrl, UriKind.Absolute, out var baseUri))
        {
            errors.Add($"{prefix}:BaseUrl must be an absolute URL.");
        }
        else if (!egressAllowlist.Contains(baseUri.Host))
        {
            errors.Add($"{prefix}:BaseUrl host '{baseUri.Host}' is not in Proxy:EgressAllowlist.");
        }

        // AuthType
        if (!KnownAuthTypes.Contains(s.AuthType, StringComparer.OrdinalIgnoreCase))
        {
            errors.Add($"{prefix}:AuthType '{s.AuthType}' must be one of: {string.Join(", ", KnownAuthTypes)}.");
        }

        // AuthType-specific sub-config
        if (string.Equals(s.AuthType, "OBOToken", StringComparison.OrdinalIgnoreCase))
        {
            ValidateOboConfig(prefix, s.OBO, errors);
        }
        else if (string.Equals(s.AuthType, "EntraId", StringComparison.OrdinalIgnoreCase))
        {
            ValidateEntraIdConfig(prefix, s.EntraId, errors);
        }
        else if (string.Equals(s.AuthType, "ApiKey", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(s.ApiKey))
            {
                errors.Add($"{prefix}:ApiKey is required when AuthType=ApiKey.");
            }
        }

        // TimeoutSeconds
        if (s.TimeoutSeconds < 1 || s.TimeoutSeconds > 300)
        {
            errors.Add($"{prefix}:TimeoutSeconds must be in [1..300]; got {s.TimeoutSeconds}.");
        }
    }

    private static void ValidateOboConfig(string prefix, DownstreamServerOptions.OboOptions? obo, List<string> errors)
    {
        if (obo is null)
        {
            errors.Add($"{prefix}:OBO is required when AuthType=OBOToken.");
            return;
        }

        if (!Guid.TryParse(obo.TenantId, out _))
            errors.Add($"{prefix}:OBO:TenantId must be a GUID.");
        if (!Guid.TryParse(obo.ClientId, out _))
            errors.Add($"{prefix}:OBO:ClientId must be a GUID.");
        if (string.IsNullOrWhiteSpace(obo.ClientSecret))
            errors.Add($"{prefix}:OBO:ClientSecret is required.");
        if (string.IsNullOrWhiteSpace(obo.TargetScope) || !obo.TargetScope.Contains('/'))
            errors.Add($"{prefix}:OBO:TargetScope must match '{{resource-id}}/{{scope}}'.");
    }

    private static void ValidateEntraIdConfig(string prefix, DownstreamServerOptions.EntraIdAuthOptions? entra, List<string> errors)
    {
        if (entra is null)
        {
            errors.Add($"{prefix}:EntraId is required when AuthType=EntraId.");
            return;
        }

        if (!Guid.TryParse(entra.TenantId, out _))
            errors.Add($"{prefix}:EntraId:TenantId must be a GUID.");
        if (!Guid.TryParse(entra.ClientId, out _))
            errors.Add($"{prefix}:EntraId:ClientId must be a GUID.");
        if (string.IsNullOrWhiteSpace(entra.ClientSecret))
            errors.Add($"{prefix}:EntraId:ClientSecret is required.");
        if (string.IsNullOrWhiteSpace(entra.Scope))
            errors.Add($"{prefix}:EntraId:Scope is required.");
    }
}
