using System.Collections.Generic;

namespace EntraMcpProxy.Configuration;

/// <summary>
/// Optional per-tool authorization policy. Bound from the
/// "Proxy:Authorization" configuration section.
///
/// CLAUDE.AI COMPATIBILITY DEFAULT: when this section is absent OR
/// when <see cref="Tools"/> is empty, every authenticated user sees
/// and can call every registered tool. This matches the pre-Phase-11
/// behavior and is the secure default for a single-downstream rollout
/// where the downstream enforces its own ACLs.
///
/// When <see cref="Tools"/> is non-empty, the rules are:
/// 1. For each tool the user wants to LIST or CALL, find the most-
///    specific matching pattern. Wildcards work as
///    suffix match: 'azdevops__*' matches 'azdevops__create_work_item'.
///    Exact names beat wildcards.
/// 2. If no pattern matches, the tool is ALLOWED (permit-by-default).
///    Operators who want deny-by-default must explicitly add a '*'
///    catch-all rule with an empty AllowedGroups list.
/// 3. If a matching pattern's AllowedGroups list intersects the user's
///    'groups' claim, the call is permitted. Otherwise denied with
///    MCP error 'not_authorized'.
/// </summary>
public sealed record AuthorizationPolicyOptions
{
    public Dictionary<string, AuthorizationToolRule> Tools { get; init; } = new();

    public sealed record AuthorizationToolRule
    {
        public List<string> AllowedGroups { get; init; } = new();
    }
}
