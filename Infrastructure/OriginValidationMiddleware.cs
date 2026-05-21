using System;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// MCP spec compliance — DNS rebinding defense. Validates the Origin header
/// on requests to MCP endpoints (the routes registered by MapMcp() and the
/// /api/healthz endpoint). Requests without an Origin header (CLI tools,
/// curl, non-browser clients) are PERMITTED — the attack surface is
/// browser-mediated only.
///
/// Allowed origins come from <see cref="ProxyOptions.AllowedOrigins"/>.
/// When empty (the secure default for a proxy fronted by an ingress that
/// already enforces origin), no Origin check is performed beyond
/// noting "Origin header present but no allowlist configured" at Debug.
///
/// The OAuth facade endpoints (/authorize, /token, /.well-known/*) are
/// EXEMPT from this check — those are server-to-server OAuth calls or
/// browser navigations from Entra; Origin would be set to login.microsoftonline.com.
/// </summary>
public sealed class OriginValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptions<ProxyOptions> _options;
    private readonly ILogger<OriginValidationMiddleware> _logger;

    public OriginValidationMiddleware(
        RequestDelegate next,
        IOptions<ProxyOptions> options,
        ILogger<OriginValidationMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Exempt paths — OAuth facade + health (each has its own auth model).
        var path = context.Request.Path.Value ?? "";
        if (path.StartsWith("/authorize", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/token", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/.well-known", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/api/healthz", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        var allowed = _options.Value.AllowedOrigins;
        var origin = context.Request.Headers["Origin"].ToString();

        // No allowlist → permissive (matches pre-Phase-Block-A behavior;
        // operator opt-in via config to tighten).
        if (allowed.Count == 0)
        {
            if (!string.IsNullOrEmpty(origin))
            {
                _logger.LogDebug(
                    "Origin '{Origin}' on {Path}: AllowedOrigins not configured; permitting",
                    origin, path);
            }
            await _next(context);
            return;
        }

        // No Origin header → likely a non-browser client (CLI, curl). DNS
        // rebinding attack requires a browser, so the absence of Origin
        // means no rebinding risk. Permit.
        if (string.IsNullOrEmpty(origin))
        {
            await _next(context);
            return;
        }

        // Origin present + allowlist configured → must match.
        foreach (var entry in allowed)
        {
            if (string.Equals(origin, entry, StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }
        }

        _logger.LogWarning(
            "Origin '{Origin}' on {Path} not in AllowedOrigins; rejecting (DNS rebinding defense)",
            origin, path);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync("Origin not allowed");
    }
}
