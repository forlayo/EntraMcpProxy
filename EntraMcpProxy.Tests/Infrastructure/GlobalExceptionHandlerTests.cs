using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class GlobalExceptionHandlerTests
{
    private static GlobalExceptionHandler New(string envName) =>
        new(NullLogger<GlobalExceptionHandler>.Instance, EnvFor(envName));

    private static IHostEnvironment EnvFor(string name)
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(name);
        return env;
    }

    private static async Task<(int Status, JsonElement Body)> Invoke(
        GlobalExceptionHandler sut, Exception ex)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/test";
        ctx.Response.Body = new MemoryStream();

        var handled = await sut.TryHandleAsync(ctx, ex, CancellationToken.None);
        handled.Should().BeTrue();

        ctx.Response.Body.Position = 0;
        var json = JsonDocument.Parse(ctx.Response.Body).RootElement;
        return (ctx.Response.StatusCode, json);
    }

    [Fact]
    public async Task OboExchangeException_returns_502_with_generic_detail_in_Production()
    {
        var (status, body) = await Invoke(
            New("Production"),
            new OboExchangeException("OBO token exchange failed (401).",
                innerEntraBody: "AADSTS50001: secret leak"));
        status.Should().Be(502);
        body.GetProperty("detail").GetString()
            .Should().Contain("upstream identity provider");
        body.GetProperty("detail").GetString()
            .Should().NotContain("AADSTS");
        body.GetProperty("detail").GetString()
            .Should().NotContain("401");
        // Title is the safe Phase 14 title
        body.GetProperty("title").GetString().Should().Contain("Upstream Authentication Error");
    }

    [Fact]
    public async Task OboExchangeException_returns_502_with_full_detail_in_Development()
    {
        var (status, body) = await Invoke(
            New("Development"),
            new OboExchangeException("OBO token exchange failed (401).", innerEntraBody: null));
        status.Should().Be(502);
        // In dev the original message is exposed for debugging.
        body.GetProperty("detail").GetString().Should().Contain("(401)");
    }

    [Fact]
    public async Task ArgumentException_returns_400_with_message_in_Production()
    {
        var (status, body) = await Invoke(
            New("Production"),
            new ArgumentException("redirect_uri is invalid"));
        status.Should().Be(400);
        body.GetProperty("detail").GetString().Should().Contain("redirect_uri is invalid");
    }

    [Fact]
    public async Task Generic_InvalidOperationException_returns_400_with_message_in_Production()
    {
        // InvalidOperationException outside the Auth namespace stays 400 (client validation).
        var (status, body) = await Invoke(
            New("Production"),
            new InvalidOperationException("bad request shape"));
        status.Should().Be(400);
        body.GetProperty("detail").GetString().Should().Contain("bad request shape");
    }

    [Fact]
    public async Task Unhandled_Exception_returns_500_with_generic_message_in_Production()
    {
        var (status, body) = await Invoke(
            New("Production"),
            new ApplicationException("internal debug detail"));
        status.Should().Be(500);
        body.GetProperty("detail").GetString().Should().NotContain("internal debug detail");
        body.GetProperty("detail").GetString().Should().Contain("unexpected error");
    }

    [Fact]
    public async Task HttpRequestException_returns_BadGateway_with_generic_detail_in_Production()
    {
        var (status, body) = await Invoke(
            New("Production"),
            new HttpRequestException("egress blocked: attacker.example.com is not permitted"));
        // Without explicit StatusCode, HttpRequestException maps to 502 in the new classifier.
        status.Should().Be(502);
        body.GetProperty("detail").GetString().Should().NotContain("attacker.example.com");
    }
}
