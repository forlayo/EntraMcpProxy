using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding M8: CORS was wide open (AllowAnyOrigin). The proxy must
/// restrict cross-origin access to ProxyOptions.AllowedCorsOrigins; when
/// that list is empty (default), no cross-origin requests are honored.
/// </summary>
public class CorsRestrictionTests
{
    [Fact]
    public async Task Preflight_from_unlisted_origin_does_not_grant_AllowOrigin()
    {
        // Default factory: AllowedCorsOrigins = [] -> no origins permitted.
        await using var factory = new ProxyAppFactory();
        using var http = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Options, "/api/healthz");
        req.Headers.Add("Origin", "https://evil.example.com");
        req.Headers.Add("Access-Control-Request-Method", "GET");

        var resp = await http.SendAsync(req);

        // The proxy should NOT return the Allow-Origin header for an unlisted origin.
        resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var _)
            .Should().BeFalse("an empty AllowedCorsOrigins must not echo any origin");
    }

    [Fact]
    public async Task Preflight_from_listed_origin_grants_AllowOrigin()
    {
        await using var factory = new ListedOriginFactory("https://claude.ai");
        using var http = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Options, "/api/healthz");
        req.Headers.Add("Origin", "https://claude.ai");
        req.Headers.Add("Access-Control-Request-Method", "GET");

        var resp = await http.SendAsync(req);

        resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values!.Single().Should().Be("https://claude.ai");
    }

    [Fact]
    public async Task Preflight_from_unlisted_origin_when_other_origin_is_listed_is_blocked()
    {
        await using var factory = new ListedOriginFactory("https://claude.ai");
        using var http = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Options, "/api/healthz");
        req.Headers.Add("Origin", "https://evil.example.com");
        req.Headers.Add("Access-Control-Request-Method", "GET");

        var resp = await http.SendAsync(req);
        resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var _)
            .Should().BeFalse();
    }

    /// <summary>Factory that adds a single configured origin to AllowedCorsOrigins.</summary>
    private sealed class ListedOriginFactory : ProxyAppFactory
    {
        private readonly string _origin;
        public ListedOriginFactory(string origin) => _origin = origin;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureAppConfiguration((_, cfg) =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Proxy:AllowedCorsOrigins:0"] = _origin,
                });
            });
        }
    }
}
