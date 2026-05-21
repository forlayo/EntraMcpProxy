using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Configuration;

public class ProxyOptionsValidatorTests
{
    private static ProxyOptions Valid() => new()
    {
        PublicBaseUrl = "https://proxy.example.com",
        AllowedRedirectUris = new() { "https://claude.ai/api/mcp/auth_callback" },
        EgressAllowlist = new() { "mcp.dev.azure.com" },
        AllowedCorsOrigins = new() { "https://claude.ai" },
        RefreshIntervalMinutes = 5,
        RateLimit = new ProxyOptions.RateLimitOptions
        {
            RequestsPerMinute = 30,
        },
        ToolResult = new ProxyOptions.ToolResultOptions
        {
            MaxBytes = 256 * 1024,
        },
    };

    [Fact]
    public void Accepts_a_complete_valid_config()
    {
        new ProxyOptionsValidator().Validate(null, Valid()).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Rejects_missing_PublicBaseUrl()
    {
        var opts = Valid() with { PublicBaseUrl = "" };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("PublicBaseUrl");
    }

    [Fact]
    public void Rejects_non_https_PublicBaseUrl()
    {
        var opts = Valid() with { PublicBaseUrl = "http://proxy.example.com" };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("PublicBaseUrl").And.Contain("https");
    }

    [Fact]
    public void Rejects_non_absolute_PublicBaseUrl()
    {
        var opts = Valid() with { PublicBaseUrl = "proxy.example.com" };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("PublicBaseUrl");
    }

    [Fact]
    public void Rejects_empty_AllowedRedirectUris()
    {
        var opts = Valid() with { AllowedRedirectUris = new() };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("AllowedRedirectUris");
    }

    [Fact]
    public void Rejects_AllowedRedirectUri_that_is_not_absolute_https()
    {
        var opts = Valid() with { AllowedRedirectUris = new() { "http://localhost/cb" } };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("AllowedRedirectUris");
    }

    [Fact]
    public void Rejects_empty_EgressAllowlist()
    {
        var opts = Valid() with { EgressAllowlist = new() };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("EgressAllowlist");
    }

    [Fact]
    public void Rejects_EgressAllowlist_entry_with_scheme_or_slash()
    {
        var opts = Valid() with { EgressAllowlist = new() { "https://mcp.dev.azure.com/contoso" } };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("EgressAllowlist");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(61)]
    [InlineData(int.MaxValue)]
    public void Rejects_RefreshIntervalMinutes_out_of_bounds(int value)
    {
        var opts = Valid() with { RefreshIntervalMinutes = value };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("RefreshIntervalMinutes");
    }

    [Fact]
    public void Accepts_RefreshIntervalMinutes_at_boundary_values()
    {
        var v = new ProxyOptionsValidator();
        v.Validate(null, Valid() with { RefreshIntervalMinutes = 1  }).Succeeded.Should().BeTrue();
        v.Validate(null, Valid() with { RefreshIntervalMinutes = 60 }).Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(10_001)]
    public void Rejects_RateLimit_RequestsPerMinute_out_of_bounds(int value)
    {
        var opts = Valid() with
        {
            RateLimit = new ProxyOptions.RateLimitOptions { RequestsPerMinute = value },
        };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("RateLimit");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(8 * 1024 * 1024 + 1)] // > 8 MiB upper bound
    public void Rejects_ToolResult_MaxBytes_out_of_bounds(int value)
    {
        var opts = Valid() with
        {
            ToolResult = new ProxyOptions.ToolResultOptions { MaxBytes = value },
        };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("ToolResult");
    }

    [Fact]
    public void Aggregates_all_errors_in_one_message()
    {
        var opts = new ProxyOptions
        {
            PublicBaseUrl = "",
            AllowedRedirectUris = new(),
            EgressAllowlist = new(),
            RefreshIntervalMinutes = 0,
            RateLimit = new() { RequestsPerMinute = 0 },
            ToolResult = new() { MaxBytes = 0 },
        };
        var result = new ProxyOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        // Each field name should appear
        result.FailureMessage!.Should().Contain("PublicBaseUrl");
        result.FailureMessage.Should().Contain("AllowedRedirectUris");
        result.FailureMessage.Should().Contain("EgressAllowlist");
        result.FailureMessage.Should().Contain("RefreshIntervalMinutes");
        result.FailureMessage.Should().Contain("RateLimit");
        result.FailureMessage.Should().Contain("ToolResult");
    }

    [Fact]
    public void AllowedCorsOrigins_may_be_empty_by_default()
    {
        // CORS being empty is a *more restrictive* posture, not an error.
        var opts = Valid() with { AllowedCorsOrigins = new() };
        new ProxyOptionsValidator().Validate(null, opts).Succeeded.Should().BeTrue();
    }
}
