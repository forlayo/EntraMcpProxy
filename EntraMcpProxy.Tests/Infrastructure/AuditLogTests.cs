using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using EntraMcpProxy.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace EntraMcpProxy.Tests.Infrastructure;

public class AuditLogTests
{
    private readonly TestSink _sink;
    private readonly ILoggerFactory _factory;

    public AuditLogTests()
    {
        _sink = new TestSink();
        _factory = LoggerFactory.Create(b => b.AddProvider(_sink));
    }

    private AuditLog NewSut() => new(_factory);

    private static ClaimsPrincipal User(string oid = "alice", string tid = "tenant")
        => new(new ClaimsIdentity(new[] { new Claim("oid", oid), new Claim("tid", tid) }, "test"));

    [Fact]
    public void ToolInvocation_emits_structured_json_under_audit_category()
    {
        NewSut().ToolInvocation(User(), "azdevops__ping", args: new { x = 1 },
            status: "success", latencyMs: 42, correlationId: "corr-1");

        _sink.Captured.Should().ContainSingle();
        var record = _sink.Captured[0];
        record.Category.Should().Be("EntraMcpProxy.Audit");
        var json = JsonDocument.Parse(record.Message).RootElement;
        json.GetProperty("event").GetString().Should().Be("tool_invocation");
        json.GetProperty("user_oid").GetString().Should().Be("alice");
        json.GetProperty("tool").GetString().Should().Be("azdevops__ping");
        json.GetProperty("downstream_status").GetString().Should().Be("success");
        json.GetProperty("latency_ms").GetInt64().Should().Be(42);
        json.GetProperty("correlation_id").GetString().Should().Be("corr-1");
        // args is hashed, never plaintext
        json.GetProperty("args_sha256").GetString().Should().HaveLength(64);
        json.ToString().Should().NotContain("\"x\":1", "args must be hashed, not plaintext");
    }

    [Fact]
    public void ToolInvocation_with_null_args_emits_null_args_sha256()
    {
        NewSut().ToolInvocation(User(), "tool", args: null, status: "success", latencyMs: 1);
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("args_sha256").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public void AuthzDenied_includes_user_and_tool_and_reason()
    {
        NewSut().AuthzDenied(User(oid: "bob"), "restricted__tool", reason: "not in group");
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("event").GetString().Should().Be("authz_denied");
        json.GetProperty("user_oid").GetString().Should().Be("bob");
        json.GetProperty("tool").GetString().Should().Be("restricted__tool");
        json.GetProperty("reason").GetString().Should().Be("not in group");
    }

    [Fact]
    public void OboExchangeFailed_with_null_user_does_not_throw()
    {
        NewSut().OboExchangeFailed(user: null, targetScope: "api://x", error: "AADSTS50000");
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("user_oid").ValueKind.Should().Be(JsonValueKind.Null);
        json.GetProperty("target_scope").GetString().Should().Be("api://x");
    }

    [Fact]
    public void PkceMissing_records_client_ip()
    {
        NewSut().PkceMissing(clientIp: "203.0.113.5", error: "code_challenge missing");
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("event").GetString().Should().Be("pkce_missing");
        json.GetProperty("client_ip").GetString().Should().Be("203.0.113.5");
    }

    [Fact]
    public void RedirectUriRejected_records_rejected_uri()
    {
        NewSut().RedirectUriRejected(clientIp: "203.0.113.5", rejectedUri: "https://evil.example.com/cb");
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("event").GetString().Should().Be("redirect_uri_rejected");
        json.GetProperty("rejected_uri").GetString().Should().Be("https://evil.example.com/cb");
    }

    [Fact]
    public void ToolSetChanged_records_added_removed_changed()
    {
        NewSut().ToolSetChanged("azdevops",
            added: new[] { "new_tool" },
            removed: new[] { "old_tool" },
            descriptionChanged: new[] { "edited_tool" });
        var json = JsonDocument.Parse(_sink.Captured[0].Message).RootElement;
        json.GetProperty("downstream").GetString().Should().Be("azdevops");
        json.GetProperty("added")[0].GetString().Should().Be("new_tool");
        json.GetProperty("removed")[0].GetString().Should().Be("old_tool");
        json.GetProperty("description_changed")[0].GetString().Should().Be("edited_tool");
    }

    private sealed class TestSink : ILoggerProvider
    {
        public List<(string Category, string Message)> Captured { get; } = new();
        public ILogger CreateLogger(string categoryName) => new SinkLogger(categoryName, this);
        public void Dispose() { }

        private sealed class SinkLogger : ILogger
        {
            private readonly string _category;
            private readonly TestSink _sink;
            public SinkLogger(string category, TestSink sink) { _category = category; _sink = sink; }
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => new NoopScope();
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, System.Exception? exception, System.Func<TState, System.Exception?, string> formatter)
                => _sink.Captured.Add((_category, formatter(state, exception)));
            private sealed class NoopScope : IDisposable { public void Dispose() { } }
        }
    }
}
