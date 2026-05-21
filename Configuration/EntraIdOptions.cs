using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Configuration;

/// <summary>
/// Strongly-typed Entra ID authentication settings. Bound from the
/// "EntraId" configuration section at startup.
///
/// All three of Authority, TenantId, ClientId are required and validated
/// by <see cref="EntraIdOptionsValidator"/>. RequireHttpsMetadata defaults
/// to <c>true</c>; only override for local development.
/// </summary>
public sealed record EntraIdOptions
{
    public string Authority { get; init; } = "";
    public string TenantId  { get; init; } = "";
    public string ClientId  { get; init; } = "";
    public bool RequireHttpsMetadata { get; init; } = true;
}

/// <summary>
/// Validates <see cref="EntraIdOptions"/> at application startup.
/// All errors are aggregated into a single failure message so the
/// operator sees every misconfiguration in one shot.
/// </summary>
public sealed class EntraIdOptionsValidator : IValidateOptions<EntraIdOptions>
{
    public ValidateOptionsResult Validate(string? name, EntraIdOptions options)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            errors.Add("EntraId:Authority is required.");
        }
        else if (!System.Uri.TryCreate(options.Authority, System.UriKind.Absolute, out _))
        {
            errors.Add("EntraId:Authority must be an absolute URL.");
        }

        if (!System.Guid.TryParse(options.TenantId, out _))
        {
            errors.Add("EntraId:TenantId must be a GUID.");
        }

        if (!System.Guid.TryParse(options.ClientId, out _))
        {
            errors.Add("EntraId:ClientId must be a GUID.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(string.Join("; ", errors));
    }
}
