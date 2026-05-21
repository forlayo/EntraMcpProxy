using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class EgressAllowlistTests
{
    private static EgressAllowlist New(params string[] hosts) =>
        new(Options.Create(new ProxyOptions
        {
            EgressAllowlist = new List<string>(hosts),
        }));

    [Fact]
    public void Allows_listed_host() => New("mcp.dev.azure.com")
        .IsAllowed("mcp.dev.azure.com").Should().BeTrue();

    [Fact]
    public void Rejects_unlisted_host() => New("mcp.dev.azure.com")
        .IsAllowed("attacker.example.com").Should().BeFalse();

    [Fact]
    public void Always_permits_login_microsoftonline_com_regardless_of_list()
    {
        New().IsAllowed("login.microsoftonline.com").Should().BeTrue();
        New("nothing-else.test").IsAllowed("login.microsoftonline.com").Should().BeTrue();
    }

    [Fact]
    public void Comparison_is_case_insensitive()
    {
        New("Mcp.Dev.Azure.Com").IsAllowed("mcp.DEV.azure.com").Should().BeTrue();
    }

    [Fact]
    public void Empty_or_whitespace_host_is_rejected()
    {
        New("anything.test").IsAllowed("").Should().BeFalse();
        New("anything.test").IsAllowed("   ").Should().BeFalse();
    }
}
