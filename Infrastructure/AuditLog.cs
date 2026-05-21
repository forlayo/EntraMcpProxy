using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Single facade for emitting security-relevant audit events as
/// structured JSON via the dedicated logger category
/// "EntraMcpProxy.Audit". Operators are expected to pipe this category
/// to an immutable store (Azure Monitor with immutability policy,
/// SIEM, etc.).
///
/// Args are SHA-256 hashed before logging — never plaintext — to
/// prevent PII / business-data leakage into the audit stream.
/// </summary>
public sealed class AuditLog
{
    private readonly ILogger _logger;

    public AuditLog(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger("EntraMcpProxy.Audit");
    }

    public void ToolInvocation(
        ClaimsPrincipal user,
        string tool,
        object? args,
        string status,
        long latencyMs,
        string? correlationId = null)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "tool_invocation",
            user_oid = user.FindFirst("oid")?.Value,
            user_tid = user.FindFirst("tid")?.Value,
            tool,
            args_sha256 = HashArgs(args),
            downstream_status = status,
            latency_ms = latencyMs,
            correlation_id = correlationId,
        });
    }

    public void ToolSetChanged(
        string downstreamPrefix,
        IReadOnlyList<string> added,
        IReadOnlyList<string> removed,
        IReadOnlyList<string> descriptionChanged)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "tool_set_changed",
            downstream = downstreamPrefix,
            added,
            removed,
            description_changed = descriptionChanged,
        });
    }

    public void AuthzDenied(
        ClaimsPrincipal user,
        string tool,
        string reason)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "authz_denied",
            user_oid = user.FindFirst("oid")?.Value,
            user_tid = user.FindFirst("tid")?.Value,
            tool,
            reason,
        });
    }

    public void OboExchangeFailed(
        ClaimsPrincipal? user,
        string targetScope,
        string error)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "obo_exchange_failed",
            user_oid = user?.FindFirst("oid")?.Value,
            user_tid = user?.FindFirst("tid")?.Value,
            target_scope = targetScope,
            error,
        });
    }

    public void PkceMissing(string clientIp, string error)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "pkce_missing",
            client_ip = clientIp,
            error,
        });
    }

    public void RedirectUriRejected(string clientIp, string rejectedUri)
    {
        Emit(new
        {
            ts = DateTime.UtcNow.ToString("o"),
            @event = "redirect_uri_rejected",
            client_ip = clientIp,
            rejected_uri = rejectedUri,
        });
    }

    private void Emit(object record)
    {
        string json = JsonSerializer.Serialize(record);
        _logger.LogInformation("{AuditJson}", json);
    }

    private static string? HashArgs(object? args)
    {
        if (args is null) return null;
        var serialized = JsonSerializer.Serialize(args);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(serialized), hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
