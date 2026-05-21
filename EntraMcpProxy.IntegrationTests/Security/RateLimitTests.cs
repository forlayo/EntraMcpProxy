using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

/// <summary>
/// Audit finding M10: no rate limiting on /authorize or /token allows an
/// attacker to flood the proxy as a relay to Entra. Enforce a fixed-window
/// per-IP cap configurable via Proxy:RateLimit:RequestsPerMinute.
/// </summary>
public class RateLimitTests
{
    [Fact]
    public async Task Token_returns_429_when_per_minute_cap_exceeded()
    {
        // Tight 3-per-minute cap so the test is fast.
        await using var factory = new TightLimitFactory(perMinute: 3);
        using var http = factory.CreateClient();

        async Task<HttpResponseMessage> Post() =>
            await http.PostAsync("/token",
                new StringContent("grant_type=authorization_code&code=x&code_verifier=v",
                    Encoding.UTF8, "application/x-www-form-urlencoded"));

        // First 3 should not be 429 (they'll likely be 4xx/5xx for various
        // reasons — Entra isn't real here — but NOT 429).
        for (int i = 0; i < 3; i++)
        {
            var resp = await Post();
            resp.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
        }

        // 4th must be 429.
        var fourth = await Post();
        fourth.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Authorize_returns_429_when_per_minute_cap_exceeded()
    {
        await using var factory = new TightLimitFactory(perMinute: 3);
        using var http = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

        var url = "/authorize?response_type=code" +
                  "&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback" +
                  "&state=abc&code_challenge=abcd1234ABCD-_56abcd1234ABCD-_56abcd1234ABC&code_challenge_method=S256";

        for (int i = 0; i < 3; i++)
        {
            var resp = await http.GetAsync(url);
            resp.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
        }

        var fourth = await http.GetAsync(url);
        fourth.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }

    [Fact]
    public async Task Healthz_is_not_rate_limited()
    {
        // /api/healthz must remain available even under heavy load.
        await using var factory = new TightLimitFactory(perMinute: 3);
        using var http = factory.CreateClient();

        for (int i = 0; i < 10; i++)
        {
            var resp = await http.GetAsync("/api/healthz");
            resp.StatusCode.Should().NotBe(HttpStatusCode.TooManyRequests);
        }
    }

    private sealed class TightLimitFactory : ProxyAppFactory
    {
        private readonly int _perMinute;
        public TightLimitFactory(int perMinute) => _perMinute = perMinute;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureAppConfiguration((_, cfg) =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Proxy:RateLimit:RequestsPerMinute"] = _perMinute.ToString(),
                });
            });
        }
    }
}
