using EntraMcpProxy.Configuration;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Configuration;

public class EntraIdOptionsValidatorTests
{
    private static EntraIdOptions Valid() => new()
    {
        Authority = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
        TenantId  = "11111111-1111-1111-1111-111111111111",
        ClientId  = "22222222-2222-2222-2222-222222222222",
        RequireHttpsMetadata = true,
    };

    [Fact]
    public void Accepts_a_complete_valid_config()
    {
        var result = new EntraIdOptionsValidator().Validate(name: null, options: Valid());
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Rejects_missing_authority()
    {
        var opts = Valid() with { Authority = "" };
        var result = new EntraIdOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("Authority");
    }

    [Fact]
    public void Rejects_non_absolute_authority()
    {
        var opts = Valid() with { Authority = "login.microsoftonline.com/abc/v2.0" };
        var result = new EntraIdOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("Authority");
    }

    [Fact]
    public void Rejects_non_guid_tenantId()
    {
        var opts = Valid() with { TenantId = "not-a-guid" };
        var result = new EntraIdOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("TenantId");
    }

    [Fact]
    public void Rejects_non_guid_clientId()
    {
        var opts = Valid() with { ClientId = "abc" };
        var result = new EntraIdOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        result.FailureMessage!.Should().Contain("ClientId");
    }

    [Fact]
    public void Aggregates_all_errors_in_one_message()
    {
        var opts = new EntraIdOptions
        {
            Authority = "",
            TenantId  = "bad",
            ClientId  = "bad",
        };
        var result = new EntraIdOptionsValidator().Validate(null, opts);
        result.Failed.Should().BeTrue();
        // All three field names should appear
        result.FailureMessage!.Should().Contain("Authority");
        result.FailureMessage.Should().Contain("TenantId");
        result.FailureMessage.Should().Contain("ClientId");
    }

    [Fact]
    public void RequireHttpsMetadata_defaults_to_true()
    {
        new EntraIdOptions().RequireHttpsMetadata.Should().BeTrue();
    }
}
