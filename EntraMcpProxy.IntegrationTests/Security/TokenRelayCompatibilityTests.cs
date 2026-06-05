using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.IntegrationTests.Fixtures;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace EntraMcpProxy.IntegrationTests.Security;

public class TokenRelayCompatibilityTests
{
    [Fact]
    public async Task Token_relay_translates_claude_resource_to_entra_scope_with_offline_access()
    {
        var relay = new CapturingTokenRelay();
        await using var factory = new CapturingProxyAppFactory(relay);
        using var http = factory.CreateClient();

        var body =
            "grant_type=authorization_code" +
            "&code=auth-code" +
            "&code_verifier=verifier" +
            "&client_id=00000000-0000-0000-0000-000000000002" +
            "&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback" +
            "&resource=https%3A%2F%2Fproxy.test%2Fmcp";

        var resp = await http.PostAsync(
            "/token",
            new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"));

        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        relay.LastClientName.Should().Be("entra-token-relay");
        relay.LastBody.Should().NotBeNull();
        relay.LastBody.Should().NotContain("resource=");
        relay.LastBody.Should().Contain("grant_type=authorization_code");
        relay.LastBody.Should().Contain("scope=");
        relay.LastBody.Should().Contain("offline_access");
        relay.LastBody.Should().Contain("api%3A%2F%2F00000000-0000-0000-0000-000000000002%2Fuser_impersonation");
    }

    private sealed class CapturingProxyAppFactory : ProxyAppFactory
    {
        private readonly CapturingTokenRelay _relay;

        public CapturingProxyAppFactory(CapturingTokenRelay relay)
        {
            _relay = relay;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHttpClientFactory>();
                services.AddSingleton<IHttpClientFactory>(_relay);
            });
        }
    }

    private sealed class CapturingTokenRelay : IHttpClientFactory
    {
        public string? LastClientName { get; private set; }
        public string? LastBody { get; private set; }

        public HttpClient CreateClient(string name)
        {
            LastClientName = name;
            return new HttpClient(new CapturingHandler(this));
        }

        private sealed class CapturingHandler : HttpMessageHandler
        {
            private readonly CapturingTokenRelay _relay;

            public CapturingHandler(CapturingTokenRelay relay)
            {
                _relay = relay;
            }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                _relay.LastBody = request.Content is null
                    ? null
                    : await request.Content.ReadAsStringAsync(cancellationToken);

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh"}""",
                        Encoding.UTF8,
                        "application/json"),
                };
            }
        }
    }
}
