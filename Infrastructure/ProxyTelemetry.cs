using System.Diagnostics;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Central ActivitySource for EntraMcpProxy custom tracing spans.
///
/// Register the source name with OpenTelemetry via AddSource("EntraMcpProxy")
/// in Program.cs to have spans captured and exported.
///
/// Usage:
/// <code>
///   using var activity = ProxyTelemetry.Source.StartActivity("MyOperation");
///   activity?.SetTag("key", "value");
/// </code>
/// </summary>
public static class ProxyTelemetry
{
    /// <summary>
    /// The shared ActivitySource.  StartActivity returns null when no listener
    /// is registered (OTel not configured), so all callers must null-check.
    /// </summary>
    public static readonly ActivitySource Source = new("EntraMcpProxy", "1.0");
}
