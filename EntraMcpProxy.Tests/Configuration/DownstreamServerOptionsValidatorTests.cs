using System.Collections.Generic;
using EntraMcpProxy.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Configuration;

public class DownstreamServerOptionsValidatorTests
{
    private static ProxyOptions ProxyOpts() => new()
    {
        PublicBaseUrl = "https://proxy.example.com",
        AllowedRedirectUris = new() { "https://claude.ai/api/mcp/auth_callback" },
        EgressAllowlist     = new() { "mcp.dev.azure.com", "internal.example.com" },
    };

    private static DownstreamServerOptions OboServer() => new()
    {
        Name = "Azure DevOps",
        Prefix = "azdevops",
        BaseUrl = "https://mcp.dev.azure.com/contoso",
        AuthType = "OBOToken",
        OBO = new DownstreamServerOptions.OboOptions
        {
            TenantId = "11111111-1111-1111-1111-111111111111",
            ClientId = "22222222-2222-2222-2222-222222222222",
            ClientSecret = "test-secret-not-real",
            TargetScope = "2a72489c-aab2-4b65-b93a-a91edccf33b8/Ado.Mcp.Tools",
        },
        Enabled = true,
        TimeoutSeconds = 60,
    };

    private static DownstreamServerOptions EntraIdServer() => new()
    {
        Name = "Internal",
        Prefix = "internal",
        BaseUrl = "https://internal.example.com/mcp",
        AuthType = "EntraId",
        EntraId = new DownstreamServerOptions.EntraIdAuthOptions
        {
            TenantId = "11111111-1111-1111-1111-111111111111",
            ClientId = "22222222-2222-2222-2222-222222222222",
            ClientSecret = "test-secret-not-real",
            Scope = "api://internal/.default",
        },
        Enabled = true,
        TimeoutSeconds = 30,
    };

    private static DownstreamServerOptions ApiKeyServer() => new()
    {
        Name = "Legacy",
        Prefix = "legacy",
        BaseUrl = "https://internal.example.com/legacy",
        AuthType = "ApiKey",
        ApiKey = "secret-not-real",
    };

    private static DownstreamServerOptionsValidator NewValidator() =>
        new(Options.Create(ProxyOpts()));

    [Fact]
    public void Accepts_a_valid_obo_server()
    {
        NewValidator().Validate(null, new() { OboServer() }).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Accepts_a_valid_entra_id_server()
    {
        NewValidator().Validate(null, new() { EntraIdServer() }).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Accepts_a_valid_api_key_server()
    {
        NewValidator().Validate(null, new() { ApiKeyServer() }).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Accepts_empty_list()
    {
        // No downstreams is acceptable — proxy still functions for OAuth facade only.
        NewValidator().Validate(null, new List<DownstreamServerOptions>()).Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("Prefix__contains")]
    [InlineData("UPPER")]
    [InlineData("1starts-with-digit")]
    [InlineData("has space")]
    [InlineData("waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaytoolongtoolongtoolongprefix")]
    public void Rejects_invalid_Prefix(string badPrefix)
    {
        var s = OboServer() with { Prefix = badPrefix };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("Prefix");
    }

    [Fact]
    public void Rejects_missing_BaseUrl()
    {
        var s = OboServer() with { BaseUrl = "" };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("BaseUrl");
    }

    [Fact]
    public void Rejects_BaseUrl_host_not_in_EgressAllowlist()
    {
        var s = OboServer() with { BaseUrl = "https://attacker.example.com/whatever" };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("EgressAllowlist");
    }

    [Fact]
    public void Rejects_unknown_AuthType()
    {
        var s = OboServer() with { AuthType = "MagicAuth" };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("AuthType");
    }

    [Fact]
    public void Rejects_OBOToken_without_OBO_config()
    {
        var s = OboServer() with { OBO = null };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("OBO");
    }

    [Fact]
    public void Rejects_OBOToken_missing_ClientSecret()
    {
        var s = OboServer() with { OBO = OboServer().OBO! with { ClientSecret = "" } };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("ClientSecret");
    }

    [Fact]
    public void Rejects_OBOToken_missing_TargetScope()
    {
        var s = OboServer() with { OBO = OboServer().OBO! with { TargetScope = "" } };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("TargetScope");
    }

    [Fact]
    public void Rejects_OBOToken_TargetScope_wrong_shape()
    {
        var s = OboServer() with { OBO = OboServer().OBO! with { TargetScope = "no-slash-here" } };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("TargetScope");
    }

    [Fact]
    public void Rejects_EntraId_without_EntraId_config()
    {
        var s = EntraIdServer() with { EntraId = null };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("EntraId");
    }

    [Fact]
    public void Rejects_ApiKey_without_ApiKey_value()
    {
        var s = ApiKeyServer() with { ApiKey = null };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("ApiKey");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    public void Rejects_TimeoutSeconds_out_of_bounds(int value)
    {
        var s = OboServer() with { TimeoutSeconds = value };
        var r = NewValidator().Validate(null, new() { s });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("TimeoutSeconds");
    }

    [Fact]
    public void Rejects_duplicate_prefix()
    {
        var s1 = OboServer();
        var s2 = OboServer() with { Name = "duplicate" }; // same Prefix
        var r = NewValidator().Validate(null, new() { s1, s2 });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("duplicate");
    }

    [Fact]
    public void Aggregates_errors_from_multiple_servers()
    {
        var bad1 = OboServer() with { Prefix = "BAD" };           // bad prefix
        var bad2 = OboServer() with { Prefix = "ok", BaseUrl = "https://attacker.example.com" }; // not in allowlist
        var r = NewValidator().Validate(null, new() { bad1, bad2 });
        r.Failed.Should().BeTrue();
        r.FailureMessage!.Should().Contain("Prefix");
        r.FailureMessage.Should().Contain("EgressAllowlist");
    }
}
