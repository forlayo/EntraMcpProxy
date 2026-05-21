using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EntraMcpProxy.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// When ProxyOptions.LogOAuthRequests=true, emits a structured INFO-level
/// log entry for every incoming /authorize and /token request with:
/// - HTTP method + path + query string (redacted)
/// - Selected request headers (User-Agent, Origin, Accept, Content-Type)
/// - For /token: the form fields (NOT the values — only the field names,
///   except grant_type which is logged in plaintext for diagnostics)
/// - Response status code
///
/// Designed to be flipped on during the first claude.ai integration so
/// operators can see exactly what shape the connector sends. NEVER logs
/// token values, code_verifier, code, or client_secret — only field
/// presence + values explicitly safe for diagnostics.
///
/// Off by default. Should be turned OFF after first-integration is
/// validated.
/// </summary>
public sealed class OAuthRequestLoggingMiddleware
{
    private static readonly string[] LoggedHeaders =
        { "User-Agent", "Origin", "Accept", "Content-Type", "Host", "Referer" };

    private static readonly string[] PlaintextSafeFormFields =
        { "grant_type", "code_challenge_method", "response_type", "scope" };

    private readonly RequestDelegate _next;
    private readonly IOptions<ProxyOptions> _options;
    private readonly ILogger<OAuthRequestLoggingMiddleware> _logger;

    public OAuthRequestLoggingMiddleware(
        RequestDelegate next,
        IOptions<ProxyOptions> options,
        ILogger<OAuthRequestLoggingMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.Value.LogOAuthRequests)
        {
            await _next(context);
            return;
        }

        var path = context.Request.Path.Value ?? "";
        bool oauth = path.StartsWith("/authorize", StringComparison.OrdinalIgnoreCase)
                  || path.StartsWith("/token",     StringComparison.OrdinalIgnoreCase);
        if (!oauth)
        {
            await _next(context);
            return;
        }

        var sb = new StringBuilder();
        sb.Append("oauth-request method=").Append(context.Request.Method);
        sb.Append(" path=").Append(path);

        if (context.Request.Method == "GET" && context.Request.QueryString.HasValue)
        {
            sb.Append(" query=").Append(RedactQuery(context.Request.QueryString.Value));
        }

        foreach (var header in LoggedHeaders)
        {
            if (context.Request.Headers.TryGetValue(header, out var values) && values.Count > 0)
            {
                sb.Append(' ').Append(header).Append('=').Append(values[0]);
            }
        }

        if (context.Request.Method == "POST" && context.Request.HasFormContentType)
        {
            // EnableBuffering so the body stream is seekable; the downstream
            // /token handler will then be able to re-read from position 0.
            context.Request.EnableBuffering();
            try
            {
                var form = await context.Request.ReadFormAsync();
                sb.Append(" form-fields=").Append(string.Join(",", form.Keys));
                foreach (var safe in PlaintextSafeFormFields)
                {
                    if (form.TryGetValue(safe, out var v))
                    {
                        sb.Append(' ').Append(safe).Append('=').Append(v.ToString());
                    }
                }
                // Reset so downstream handlers can read the body again.
                context.Request.Body.Position = 0;
            }
            catch (Exception ex)
            {
                sb.Append(" form-read-error=").Append(ex.GetType().Name);
            }
        }

        await _next(context);

        sb.Append(" response-status=").Append(context.Response.StatusCode);
        _logger.LogInformation("{OAuthRequest}", sb.ToString());
    }

    private static string RedactQuery(string? query)
    {
        if (string.IsNullOrEmpty(query)) return "";
        // Redact security-sensitive query parameters; preserve presence as key=<redacted>.
        return string.Join("&", query.TrimStart('?').Split('&').Select(kv =>
        {
            var eq = kv.IndexOf('=');
            if (eq <= 0) return kv;
            var key = kv[..eq];
            if (key is "code" or "code_challenge" or "code_verifier" or "client_secret" or "assertion" or "state")
                return $"{key}=<redacted>";
            return kv;
        }));
    }
}
