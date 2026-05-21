using System.Text.Json;
using EntraMcpProxy.Auth;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace EntraMcpProxy.Infrastructure;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;
    private readonly IHostEnvironment _environment;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger, IHostEnvironment environment)
    {
        _logger = logger;
        _environment = environment;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var (statusCode, title, hideDetail) = ClassifyException(exception);

        var detail = _environment.IsDevelopment()
            ? exception.Message
            : hideDetail
                ? GenericMessageFor(statusCode)
                : exception.Message;

        var problemDetails = new ProblemDetails
        {
            Type = $"https://httpstatuses.io/{statusCode}",
            Title = title,
            Status = statusCode,
            Detail = detail,
            Instance = httpContext.Request.Path,
        };
        problemDetails.Extensions["traceId"] = httpContext.TraceIdentifier;
        problemDetails.Extensions["timestamp"] = DateTime.UtcNow.ToString("o");

        // Log at appropriate level. ALWAYS include the full message for the
        // server-side log — clients get a sanitized view, operators get the
        // raw signal.
        _logger.Log(
            statusCode >= 500 ? LogLevel.Error : LogLevel.Warning,
            exception,
            "{StatusCode} {Title}: {Detail}",
            statusCode, title, exception.Message);

        // For OboExchangeException specifically, also log the InnerEntraBody so
        // operators can correlate AADSTS codes without exposing them to clients.
        if (exception is OboExchangeException obo && obo.InnerEntraBody is { } body)
        {
            _logger.LogDebug("Inner Entra body: {Body}", body);
        }

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/problem+json";
        await httpContext.Response.WriteAsync(
            JsonSerializer.Serialize(problemDetails, JsonOptions),
            cancellationToken);

        return true;
    }

    private static (int statusCode, string title, bool hideDetail) ClassifyException(Exception exception)
    {
        // OBO exchange failures: 502 Bad Gateway. Detail hidden in prod —
        // the message can carry AADSTS codes or other Entra hints.
        if (exception is OboExchangeException)
        {
            return (502, "Upstream Authentication Error", hideDetail: true);
        }

        // InvalidOperationException FROM the auth namespace: also a 502 — Entra-
        // related, sanitize. Other InvalidOperationException stays 400 (likely
        // client validation).
        if (exception is InvalidOperationException
            && (exception.TargetSite?.DeclaringType?.Namespace?.StartsWith("EntraMcpProxy.Auth") ?? false))
        {
            return (502, "Upstream Authentication Error", hideDetail: true);
        }

        return exception switch
        {
            HttpRequestException httpEx => ((int)(httpEx.StatusCode ?? System.Net.HttpStatusCode.BadGateway),
                                            "External API Error",
                                            hideDetail: true),
            OperationCanceledException  => (499, "Request Cancelled", hideDetail: false),
            ArgumentException           => (400, "Validation Error", hideDetail: false),
            InvalidOperationException   => (400, "Invalid Operation", hideDetail: false),
            _                           => (500, "Internal Server Error", hideDetail: true),
        };
    }

    private static string GenericMessageFor(int statusCode) => statusCode switch
    {
        502 => "An error occurred contacting the upstream identity provider.",
        >= 500 => "An unexpected error occurred.",
        _ => "Request could not be processed.",
    };
}
