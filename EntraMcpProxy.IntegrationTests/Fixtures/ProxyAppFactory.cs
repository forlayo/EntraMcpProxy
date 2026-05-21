using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace EntraMcpProxy.IntegrationTests.Fixtures;

/// <summary>
/// Boots EntraMcpProxy in-process for integration tests, with all configuration provided
/// via an in-memory configuration source so each test fixture is hermetic.
///
/// Default values are safe placeholders — tests should override fields before calling
/// CreateClient() if they need specific endpoints.
/// </summary>
public class ProxyAppFactory : WebApplicationFactory<Program>
{
    public string EntraAuthority   { get; init; } = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0";
    public string TenantId         { get; init; } = "00000000-0000-0000-0000-000000000001";
    public string ClientId         { get; init; } = "00000000-0000-0000-0000-000000000002";
    public string PublicBaseUrl    { get; init; } = "https://proxy.test";
    public bool   RequireHttps     { get; init; } = false;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("IntegrationTest");
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EntraId:Authority"]            = EntraAuthority,
                ["EntraId:TenantId"]             = TenantId,
                ["EntraId:ClientId"]             = ClientId,
                ["EntraId:RequireHttpsMetadata"] = RequireHttps ? "true" : "false",
                ["Proxy:PublicBaseUrl"]          = PublicBaseUrl,
            });
        });
    }
}
