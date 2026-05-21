using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Auth;

/// <summary>
/// Decides whether a given authenticated user is authorized to LIST or
/// CALL a given prefixed tool name. See <see cref="AuthorizationPolicyOptions"/>
/// for the policy semantics.
/// </summary>
public sealed class DownstreamAuthorizationFilter
{
    private readonly IOptions<ProxyOptions> _options;
    public DownstreamAuthorizationFilter(IOptions<ProxyOptions> options) => _options = options;

    /// <summary>
    /// Returns true if the user is permitted to list and/or call <paramref name="prefixedToolName"/>.
    /// </summary>
    public bool IsAllowed(ClaimsPrincipal user, string prefixedToolName)
    {
        var tools = _options.Value.Authorization.Tools;
        if (tools.Count == 0)
        {
            // Permit-all default. Matches pre-Phase-11 behavior.
            return true;
        }

        var rule = FindMostSpecificRule(tools, prefixedToolName);
        if (rule is null)
        {
            // No matching rule → permit by default.
            return true;
        }

        if (rule.AllowedGroups.Count == 0)
        {
            // Explicit deny — empty allowed-groups means nobody.
            return false;
        }

        var userGroups = user.FindAll("groups").Select(c => c.Value).ToHashSet();
        return rule.AllowedGroups.Any(g => userGroups.Contains(g));
    }

    private static AuthorizationPolicyOptions.AuthorizationToolRule? FindMostSpecificRule(
        Dictionary<string, AuthorizationPolicyOptions.AuthorizationToolRule> tools,
        string toolName)
    {
        // Exact match wins.
        if (tools.TryGetValue(toolName, out var exact)) return exact;

        // Wildcard match (suffix '*'): longest prefix wins.
        AuthorizationPolicyOptions.AuthorizationToolRule? best = null;
        int bestPrefixLen = -1;
        foreach (var kvp in tools)
        {
            var pattern = kvp.Key;
            if (!pattern.EndsWith("*")) continue;
            var prefix = pattern[..^1];
            if (toolName.StartsWith(prefix) && prefix.Length > bestPrefixLen)
            {
                best = kvp.Value;
                bestPrefixLen = prefix.Length;
            }
        }
        return best;
    }
}
