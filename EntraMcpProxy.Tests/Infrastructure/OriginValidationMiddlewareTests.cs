using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

/// <summary>
/// Tests for OriginValidationMiddleware (MCP spec MUST — DNS rebinding defense).
///
/// Key behaviors:
/// - Permissive when AllowedOrigins is empty (matches pre-Block-A behavior).
/// - Permits requests that have no Origin header (non-browser clients).
/// - Permits when Origin matches an AllowedOrigins entry (case-insensitive).
/// - Rejects with 403 when Origin is present and does not match.
/// - Exempts /authorize, /token, /.well-known/*, /api/healthz entirely.
/// </summary>
public class OriginValidationMiddlewareTests
{
    private static OriginValidationMiddleware Build(IEnumerable<string>? origins = null)
    {
        var opts = Options.Create(new ProxyOptions
        {
            PublicBaseUrl       = "https://proxy.example.com",
            AllowedRedirectUris = new() { "https://claude.ai/callback" },
            EgressAllowlist     = new() { "dev.azure.com" },
            AllowedOrigins      = new(origins ?? System.Array.Empty<string>()),
        });
        return new OriginValidationMiddleware(
            _ => Task.CompletedTask,
            opts,
            NullLogger<OriginValidationMiddleware>.Instance);
    }

    private static DefaultHttpContext MakeContext(string path, string? origin = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        ctx.Response.Body = new MemoryStream();
        if (origin is not null)
            ctx.Request.Headers["Origin"] = origin;
        return ctx;
    }

    // -----------------------------------------------------------------------
    // Permissive when AllowedOrigins is empty
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Permits_when_AllowedOrigins_is_empty_and_no_origin_header()
    {
        var sut = Build(); // empty list
        var ctx = MakeContext("/mcp");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Permits_when_AllowedOrigins_is_empty_even_with_an_origin_header()
    {
        var sut = Build(); // empty list = permissive
        var ctx = MakeContext("/mcp", "https://evil.com");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(200);
    }

    // -----------------------------------------------------------------------
    // No Origin header → allow (non-browser client, no rebinding risk)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Permits_when_Origin_header_absent_even_with_strict_allowlist()
    {
        var sut = Build(new[] { "https://claude.ai" });
        var ctx = MakeContext("/mcp"); // no Origin header
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(200);
    }

    // -----------------------------------------------------------------------
    // Origin matches → allow (case-insensitive)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Permits_when_Origin_matches_exact()
    {
        var sut = Build(new[] { "https://claude.ai" });
        var ctx = MakeContext("/mcp", "https://claude.ai");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Permits_when_Origin_matches_case_insensitively()
    {
        var sut = Build(new[] { "https://Claude.AI" });
        var ctx = MakeContext("/mcp", "https://claude.ai");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(200);
    }

    // -----------------------------------------------------------------------
    // Origin present but not in allowlist → 403
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rejects_with_403_when_Origin_not_in_allowlist()
    {
        var sut = Build(new[] { "https://claude.ai" });
        var ctx = MakeContext("/mcp", "https://evil.com");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task Rejects_with_403_even_if_another_allowed_origin_exists()
    {
        var sut = Build(new[] { "https://claude.ai", "https://other-allowed.com" });
        var ctx = MakeContext("/mcp", "https://attacker.example.com");
        await sut.InvokeAsync(ctx);
        ctx.Response.StatusCode.Should().Be(403);
    }

    // -----------------------------------------------------------------------
    // Exempted paths — always pass through regardless of origin
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("/authorize")]
    [InlineData("/authorize?foo=bar")]
    [InlineData("/token")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/api/healthz")]
    public async Task Exempts_oauth_and_health_paths(string path)
    {
        var sut = Build(new[] { "https://claude.ai" }); // strict allowlist
        // Send a disallowed Origin — exempted paths must still pass through
        var ctx = MakeContext(path, "https://evil.com");
        await sut.InvokeAsync(ctx);
        // Must NOT be 403 — the middleware must have passed through
        ctx.Response.StatusCode.Should().NotBe(403);
    }
}
