using System.Collections.Generic;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Auth;

public class RedirectUriValidatorTests
{
    private static RedirectUriValidator New(params string[] allowed) =>
        new(Options.Create(new ProxyOptions
        {
            PublicBaseUrl = "https://proxy.test",
            AllowedRedirectUris = new List<string>(allowed),
            EgressAllowlist = new List<string> { "dummy.test" },
        }));

    [Fact]
    public void Accepts_exact_match_from_allowlist()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("https://claude.ai/api/mcp/auth_callback").Should().BeTrue();
    }

    [Fact]
    public void Rejects_uri_not_in_allowlist()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("https://evil.example.com/cb").Should().BeFalse();
    }

    [Fact]
    public void Rejects_null_input()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed(null).Should().BeFalse();
    }

    [Fact]
    public void Rejects_empty_input()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("").Should().BeFalse();
    }

    [Fact]
    public void Rejects_whitespace_input()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("   ").Should().BeFalse();
    }

    [Fact]
    public void Rejects_partial_prefix_match()
    {
        // Even if the input STARTS with an allowed entry, it must be EXACT.
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("https://claude.ai/api/mcp/auth_callback/extra").Should().BeFalse();
    }

    [Fact]
    public void Rejects_suffix_attack()
    {
        // claude.ai.evil.com is NOT claude.ai.
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("https://claude.ai.evil.com/api/mcp/auth_callback").Should().BeFalse();
    }

    [Fact]
    public void Rejects_javascript_scheme()
    {
        // javascript: scheme has no business being a callback target.
        New("https://claude.ai/api/mcp/auth_callback", "javascript:alert(1)")
            // Even if perversely allowlisted, the validator must additionally check scheme.
            .IsAllowed("javascript:alert(1)").Should().BeFalse();
    }

    [Fact]
    public void Rejects_data_scheme()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("data:text/html,<script>alert(1)</script>").Should().BeFalse();
    }

    [Fact]
    public void Rejects_file_scheme()
    {
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("file:///etc/passwd").Should().BeFalse();
    }

    [Fact]
    public void Rejects_http_scheme_even_if_allowlisted()
    {
        // Defense-in-depth: ProxyOptionsValidator already rejects http allowlist
        // entries, but if one ever sneaks through, this validator refuses anyway.
        New("http://example.com/cb")
            .IsAllowed("http://example.com/cb").Should().BeFalse();
    }

    [Fact]
    public void Is_case_sensitive_on_path()
    {
        // OAuth redirect_uri matching MUST be exact per RFC 6749 §3.1.2.
        // Path differences matter.
        New("https://claude.ai/api/mcp/auth_callback")
            .IsAllowed("https://claude.ai/API/MCP/AUTH_CALLBACK").Should().BeFalse();
    }

    [Fact]
    public void Accepts_one_of_multiple_allowed()
    {
        var sut = New(
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback");
        sut.IsAllowed("https://claude.com/api/mcp/auth_callback").Should().BeTrue();
    }

    [Fact]
    public void Rejects_when_allowlist_is_empty()
    {
        New().IsAllowed("https://claude.ai/api/mcp/auth_callback").Should().BeFalse();
    }
}
