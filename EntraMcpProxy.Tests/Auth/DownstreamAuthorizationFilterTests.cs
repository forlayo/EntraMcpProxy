using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Auth;

public class DownstreamAuthorizationFilterTests
{
    private static DownstreamAuthorizationFilter New(
        params (string pattern, string[] groups)[] rules)
    {
        var opts = new ProxyOptions
        {
            PublicBaseUrl = "https://x",
            AllowedRedirectUris = new() { "https://x/cb" },
            EgressAllowlist = new() { "x" },
            Authorization = new AuthorizationPolicyOptions
            {
                Tools = rules.ToDictionary(
                    r => r.pattern,
                    r => new AuthorizationPolicyOptions.AuthorizationToolRule
                    {
                        AllowedGroups = r.groups.ToList()
                    }),
            },
        };
        return new DownstreamAuthorizationFilter(Options.Create(opts));
    }

    private static ClaimsPrincipal UserWithGroups(params string[] groups)
    {
        var claims = groups.Select(g => new Claim("groups", g));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    [Fact]
    public void Permits_all_tools_by_default_when_no_rules_configured()
    {
        var filter = New();
        filter.IsAllowed(UserWithGroups(), "azdevops__anything").Should().BeTrue();
        filter.IsAllowed(new ClaimsPrincipal(new ClaimsIdentity()), "azdevops__anything").Should().BeTrue();
    }

    [Fact]
    public void Permits_user_in_allowed_group()
    {
        var filter = New(("azdevops__create_work_item", new[] { "devops-write" }));
        filter.IsAllowed(UserWithGroups("devops-write"), "azdevops__create_work_item").Should().BeTrue();
    }

    [Fact]
    public void Denies_user_not_in_allowed_groups()
    {
        var filter = New(("azdevops__create_work_item", new[] { "devops-write" }));
        filter.IsAllowed(UserWithGroups("readonly"), "azdevops__create_work_item").Should().BeFalse();
    }

    [Fact]
    public void Wildcard_pattern_matches_prefixed_tools()
    {
        var filter = New(("azdevops__*", new[] { "devops-users" }));
        filter.IsAllowed(UserWithGroups("devops-users"), "azdevops__list_projects").Should().BeTrue();
        filter.IsAllowed(UserWithGroups("other"), "azdevops__list_projects").Should().BeFalse();
    }

    [Fact]
    public void Exact_match_wins_over_wildcard()
    {
        var filter = New(
            ("azdevops__create_work_item", new[] { "devops-write" }),
            ("azdevops__*",                new[] { "devops-users" }));
        // User in devops-users (matches wildcard) but NOT devops-write (matches exact).
        // Exact match wins; user is denied.
        filter.IsAllowed(UserWithGroups("devops-users"), "azdevops__create_work_item").Should().BeFalse();
        filter.IsAllowed(UserWithGroups("devops-write"), "azdevops__create_work_item").Should().BeTrue();
    }

    [Fact]
    public void Longest_wildcard_prefix_wins()
    {
        var filter = New(
            ("azdevops__create_*", new[] { "writer" }),
            ("azdevops__*",        new[] { "reader" }));
        filter.IsAllowed(UserWithGroups("writer"), "azdevops__create_work_item").Should().BeTrue();
        filter.IsAllowed(UserWithGroups("reader"), "azdevops__create_work_item").Should().BeFalse();
        // The shorter wildcard still applies to unrelated tools.
        filter.IsAllowed(UserWithGroups("reader"), "azdevops__list_projects").Should().BeTrue();
    }

    [Fact]
    public void Empty_AllowedGroups_means_explicit_deny()
    {
        var filter = New(("azdevops__create_work_item", System.Array.Empty<string>()));
        filter.IsAllowed(UserWithGroups("anything"), "azdevops__create_work_item").Should().BeFalse();
    }

    [Fact]
    public void Permits_tool_with_no_matching_rule()
    {
        var filter = New(("azdevops__create_*", new[] { "writer" }));
        // 'azdevops__list_projects' doesn't match the create_* pattern → permit by default.
        filter.IsAllowed(UserWithGroups(), "azdevops__list_projects").Should().BeTrue();
    }

    [Fact]
    public void Catch_all_with_empty_groups_implements_deny_by_default()
    {
        var filter = New(
            ("azdevops__create_*", new[] { "writer" }),
            ("*",                  System.Array.Empty<string>()));
        // 'list_projects' falls to '*' which has empty groups → denied.
        filter.IsAllowed(UserWithGroups("writer"), "azdevops__list_projects").Should().BeFalse();
        // 'create_work_item' still allowed by the specific rule.
        filter.IsAllowed(UserWithGroups("writer"), "azdevops__create_work_item").Should().BeTrue();
    }

    [Fact]
    public void Anonymous_user_is_treated_as_member_of_no_groups()
    {
        var filter = New(("azdevops__create_*", new[] { "writer" }));
        var anon = new ClaimsPrincipal(new ClaimsIdentity());
        // No matching rule for list_projects → permit by default (still default-open).
        filter.IsAllowed(anon, "azdevops__list_projects").Should().BeTrue();
        // Matching rule needs 'writer' group → anon denied.
        filter.IsAllowed(anon, "azdevops__create_work_item").Should().BeFalse();
    }
}
