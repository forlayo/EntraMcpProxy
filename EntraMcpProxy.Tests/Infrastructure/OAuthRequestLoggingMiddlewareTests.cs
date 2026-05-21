using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

/// <summary>
/// Tests for OAuthRequestLoggingMiddleware.
///
/// Behavior under test:
/// - Silent (no log + passes through) when LogOAuthRequests=false.
/// - Only fires for /authorize and /token paths, not /mcp or other paths.
/// - Logs at Information when LogOAuthRequests=true.
/// - Redacts security-sensitive query params (code, code_challenge, code_verifier, state).
/// - On POST /token: logs form field NAMES, logs plaintext-safe field VALUES, never logs secrets.
/// - Appends response status code to the log entry.
/// </summary>
public class OAuthRequestLoggingMiddlewareTests
{
    // Collects the last log message written at Information level.
    private sealed class CapturingLogger : ILogger<OAuthRequestLoggingMiddleware>
    {
        public string? LastMessage { get; private set; }
        public LogLevel? LastLevel { get; private set; }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            System.Exception? exception,
            System.Func<TState, System.Exception?, string> formatter)
        {
            LastLevel = logLevel;
            LastMessage = formatter(state, exception);
        }
    }

    private static OAuthRequestLoggingMiddleware Build(
        bool logEnabled,
        ILogger<OAuthRequestLoggingMiddleware>? logger = null)
    {
        var opts = Options.Create(new ProxyOptions
        {
            PublicBaseUrl       = "https://proxy.example.com",
            AllowedRedirectUris = new() { "https://claude.ai/callback" },
            EgressAllowlist     = new() { "dev.azure.com" },
            LogOAuthRequests    = logEnabled,
        });
        return new OAuthRequestLoggingMiddleware(
            _ => Task.CompletedTask,
            opts,
            logger ?? NullLogger<OAuthRequestLoggingMiddleware>.Instance);
    }

    private static DefaultHttpContext GetRequest(
        string path,
        string method = "GET",
        string? queryString = null,
        string? formBody = null,
        Dictionary<string, string>? headers = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        ctx.Request.Method = method;
        ctx.Response.Body = new MemoryStream();

        if (queryString is not null)
            ctx.Request.QueryString = new QueryString(queryString);

        if (headers is not null)
        {
            foreach (var (k, v) in headers)
                ctx.Request.Headers[k] = v;
        }

        if (formBody is not null)
        {
            var bodyBytes = Encoding.UTF8.GetBytes(formBody);
            ctx.Request.Body = new MemoryStream(bodyBytes);
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            ctx.Request.ContentLength = bodyBytes.Length;
        }

        return ctx;
    }

    // -----------------------------------------------------------------------
    // LogOAuthRequests=false → silent
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Silent_when_LogOAuthRequests_is_false()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: false, logger);
        var ctx = GetRequest("/authorize", queryString: "?response_type=code&client_id=x");
        await sut.InvokeAsync(ctx);
        logger.LastMessage.Should().BeNull("no log should be emitted when disabled");
    }

    // -----------------------------------------------------------------------
    // Only fires for /authorize and /token
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Does_not_log_non_oauth_paths()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest("/mcp");
        await sut.InvokeAsync(ctx);
        logger.LastMessage.Should().BeNull("should not log for non-OAuth paths");
    }

    [Theory]
    [InlineData("/authorize")]
    [InlineData("/token")]
    public async Task Logs_for_oauth_paths(string path)
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(path);
        await sut.InvokeAsync(ctx);
        logger.LastLevel.Should().Be(LogLevel.Information);
        logger.LastMessage.Should().Contain(path);
    }

    // -----------------------------------------------------------------------
    // Redaction of security-sensitive query params
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("code")]
    [InlineData("code_challenge")]
    [InlineData("code_verifier")]
    [InlineData("state")]
    public async Task Redacts_sensitive_query_params(string sensitiveKey)
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(
            "/authorize",
            queryString: $"?{sensitiveKey}=SECRET_VALUE&response_type=code");
        await sut.InvokeAsync(ctx);

        logger.LastMessage.Should().NotContain("SECRET_VALUE",
            $"{sensitiveKey} value must be redacted");
        logger.LastMessage.Should().Contain($"{sensitiveKey}=<redacted>",
            $"{sensitiveKey} key presence must be preserved but value replaced");
    }

    [Fact]
    public async Task Does_not_redact_safe_query_params()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(
            "/authorize",
            queryString: "?response_type=code&client_id=my-client");
        await sut.InvokeAsync(ctx);

        logger.LastMessage.Should().Contain("response_type=code");
        logger.LastMessage.Should().Contain("client_id=my-client");
    }

    // -----------------------------------------------------------------------
    // POST /token form field handling
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Logs_form_field_NAMES_on_post()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        // grant_type + client_secret present; secret value must not appear.
        var ctx = GetRequest(
            "/token",
            method: "POST",
            formBody: "grant_type=authorization_code&client_secret=TOP_SECRET&code=AUTH_CODE");
        await sut.InvokeAsync(ctx);

        // Field names should be enumerated
        logger.LastMessage.Should().Contain("grant_type");
        logger.LastMessage.Should().Contain("client_secret");
        logger.LastMessage.Should().Contain("code");
    }

    [Fact]
    public async Task Does_not_log_secret_or_code_values_on_post()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(
            "/token",
            method: "POST",
            formBody: "grant_type=authorization_code&client_secret=MY_SECRET_VALUE&code=MY_AUTH_CODE&code_verifier=MY_VERIFIER");
        await sut.InvokeAsync(ctx);

        logger.LastMessage.Should().NotContain("MY_SECRET_VALUE");
        logger.LastMessage.Should().NotContain("MY_AUTH_CODE");
        logger.LastMessage.Should().NotContain("MY_VERIFIER");
    }

    [Fact]
    public async Task Logs_plaintext_safe_form_field_values()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(
            "/token",
            method: "POST",
            formBody: "grant_type=authorization_code&scope=openid+profile");
        await sut.InvokeAsync(ctx);

        // grant_type is explicitly safe and must appear in plaintext
        logger.LastMessage.Should().Contain("grant_type=authorization_code");
    }

    // -----------------------------------------------------------------------
    // Response status code is logged
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Logs_response_status_code()
    {
        var logger = new CapturingLogger();
        // Middleware with a next-delegate that sets 400
        var opts = Options.Create(new ProxyOptions
        {
            PublicBaseUrl       = "https://proxy.example.com",
            AllowedRedirectUris = new() { "https://claude.ai/callback" },
            EgressAllowlist     = new() { "dev.azure.com" },
            LogOAuthRequests    = true,
        });
        var sut = new OAuthRequestLoggingMiddleware(
            ctx => { ctx.Response.StatusCode = 400; return Task.CompletedTask; },
            opts,
            logger);

        var ctx = GetRequest("/authorize");
        await sut.InvokeAsync(ctx);

        logger.LastMessage.Should().Contain("response-status=400");
    }

    // -----------------------------------------------------------------------
    // Selected request headers are logged
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Logs_selected_request_headers()
    {
        var logger = new CapturingLogger();
        var sut = Build(logEnabled: true, logger);
        var ctx = GetRequest(
            "/authorize",
            headers: new Dictionary<string, string>
            {
                ["User-Agent"] = "ClaudeAI/1.0",
                ["Origin"]     = "https://claude.ai",
            });
        await sut.InvokeAsync(ctx);

        logger.LastMessage.Should().Contain("User-Agent=ClaudeAI/1.0");
        logger.LastMessage.Should().Contain("Origin=https://claude.ai");
    }
}
