using Prometheus;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Central registry of Prometheus metrics for EntraMcpProxy.
///
/// All counters and histograms are module-level singletons; Prometheus.NET
/// de-duplicates registrations by name, so it is safe to reference these
/// from any number of call sites.
/// </summary>
public static class ProxyMetrics
{
    /// <summary>
    /// Total tool calls routed through the proxy.
    /// Labels: downstream (server prefix), tool (prefixed name), status (success|error|exception|denied).
    /// </summary>
    public static readonly Counter ToolInvocations = Metrics.CreateCounter(
        "entra_mcp_proxy_tool_invocations_total",
        "Total tool calls handled by the proxy.",
        new CounterConfiguration { LabelNames = ["downstream", "tool", "status"] });

    /// <summary>
    /// End-to-end latency per tool call (includes OBO exchange + downstream call).
    /// Labels: downstream, tool.
    /// Buckets: 10ms … ~40s (exponential, base 2, 12 steps).
    /// </summary>
    public static readonly Histogram ToolLatency = Metrics.CreateHistogram(
        "entra_mcp_proxy_tool_latency_seconds",
        "Latency of tool calls including OBO exchange + downstream call.",
        new HistogramConfiguration
        {
            LabelNames = ["downstream", "tool"],
            Buckets = Histogram.ExponentialBuckets(0.01, 2, 12),  // 10ms .. ~40s
        });

    /// <summary>
    /// OBO token exchanges against Entra.
    /// Labels: outcome (success|error).
    /// </summary>
    public static readonly Counter OboExchanges = Metrics.CreateCounter(
        "entra_mcp_proxy_obo_exchanges_total",
        "OBO token exchanges against Entra.",
        new CounterConfiguration { LabelNames = ["outcome"] });

    /// <summary>
    /// Authorization decisions denied (user not in allowed groups for the tool).
    /// Labels: tool (prefixed name).
    /// </summary>
    public static readonly Counter AuthzDenials = Metrics.CreateCounter(
        "entra_mcp_proxy_authz_denials_total",
        "Authorization decisions denied (not in allowed groups).",
        new CounterConfiguration { LabelNames = ["tool"] });

    /// <summary>
    /// OAuth-facade rejections at /authorize and /token.
    /// Labels: reason (redirect_uri|pkce_missing|body_size|rate_limit).
    /// </summary>
    public static readonly Counter OAuthRejections = Metrics.CreateCounter(
        "entra_mcp_proxy_oauth_rejections_total",
        "OAuth-facade rejections (redirect_uri / PKCE / body-size / rate-limit).",
        new CounterConfiguration { LabelNames = ["reason"] });

    /// <summary>
    /// Current size of the OBO token cache (per handler instance).
    /// Updated by the eviction loop in EntraIdOBOHandler.
    /// </summary>
    public static readonly Gauge OboCacheSize = Metrics.CreateGauge(
        "entra_mcp_proxy_obo_cache_entries",
        "Current OBO cache size (per handler instance).");
}
