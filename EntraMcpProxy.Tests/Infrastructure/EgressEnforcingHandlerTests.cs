using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class EgressEnforcingHandlerTests
{
    private static (EgressEnforcingHandler Handler, StubInner Inner) Build(params string[] allowedHosts)
    {
        var allowlist = new EgressAllowlist(Options.Create(new ProxyOptions
        {
            EgressAllowlist = new List<string>(allowedHosts),
        }));
        var stub = new StubInner();
        var handler = new EgressEnforcingHandler(allowlist, NullLogger<EgressEnforcingHandler>.Instance)
        {
            InnerHandler = stub,
        };
        return (handler, stub);
    }

    [Fact]
    public async Task Permits_request_to_allowlisted_host()
    {
        var (handler, inner) = Build("api.test");
        using var invoker = new HttpMessageInvoker(handler);
        var resp = await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://api.test/probe"),
            CancellationToken.None);
        resp.StatusCode.Should().Be(System.Net.HttpStatusCode.OK);
        inner.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Blocks_request_to_non_allowlisted_host()
    {
        var (handler, inner) = Build("api.test");
        using var invoker = new HttpMessageInvoker(handler);
        var act = async () => await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://attacker.example.com/exfil"),
            CancellationToken.None);
        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*not permitted*");
        inner.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Permits_login_microsoftonline_com_implicitly()
    {
        var (handler, inner) = Build();   // empty allowlist
        using var invoker = new HttpMessageInvoker(handler);
        await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, "https://login.microsoftonline.com/abc/v2.0/token"),
            CancellationToken.None);
        inner.Calls.Should().Be(1);
    }

    private sealed class StubInner : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }
}
