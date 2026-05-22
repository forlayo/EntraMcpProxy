using System;
using System.Collections.Generic;
using System.Linq;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Infrastructure;

namespace EntraMcpProxy.Services;

public class ToolAggregatorService : BackgroundService
{
    private readonly DownstreamClientManager _clientManager;
    private readonly ToolRegistry _toolRegistry;
    private readonly ToolPolicyService _toolPolicy;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ToolAggregatorService> _logger;
    private readonly AuditLog _audit;

    public ToolAggregatorService(
        DownstreamClientManager clientManager,
        ToolRegistry toolRegistry,
        ToolPolicyService toolPolicy,
        IConfiguration configuration,
        ILogger<ToolAggregatorService> logger,
        AuditLog audit)
    {
        _clientManager = clientManager;
        _toolRegistry = toolRegistry;
        _toolPolicy = toolPolicy;
        _configuration = configuration;
        _logger = logger;
        _audit = audit;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial connection and discovery.
        // DiscoveryContext.Enter() opts this call chain into the SP (client_credentials)
        // fallback inside EntraIdOBOHandler, replacing the previous silent fallback
        // (audit finding H6). Without this scope, OBO-configured downstreams would
        // throw OboExchangeException during startup because no user principal exists.
        using (DiscoveryContext.Enter())
        {
            await _clientManager.ConnectAllAsync(stoppingToken);
            await DiscoverToolsAsync(stoppingToken);
        }

        var intervalMinutes = _configuration.GetValue("Proxy:RefreshIntervalMinutes", 5);
        var interval = TimeSpan.FromMinutes(intervalMinutes);

        _logger.LogInformation("Tool aggregator started. Refresh interval: {Interval} minutes", intervalMinutes);

        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            // Each periodic refresh also runs in discovery scope.
            using (DiscoveryContext.Enter())
            {
                await DiscoverToolsAsync(stoppingToken);
            }
        }
    }

    private async Task DiscoverToolsAsync(CancellationToken cancellationToken)
    {
        var previousCount = _toolRegistry.Count;

        foreach (var config in _clientManager.GetConfigs())
        {
            // Lazy downstreams cannot be discovered from this background loop
            // (no user context, no SP DiscoveryScope). They are discovered on the
            // first authenticated user request via RefreshToolsForPrefixAsync.
            if (config.RequiresUserContext) continue;

            await RefreshToolsForPrefixAsync(config.Prefix, cancellationToken);
        }

        if (_toolRegistry.Count != previousCount)
        {
            _logger.LogInformation(
                "Tool registry updated: {Count} total tools (was {Previous})",
                _toolRegistry.Count, previousCount);
        }
    }

    /// <summary>
    /// Discovers and registers tools for a single downstream by prefix. Callable
    /// from the periodic background loop (inside <see cref="DiscoveryContext"/>)
    /// or from the request path with a real user bearer token (the OBO handler
    /// chooses its token path based on those two signals).
    ///
    /// Failures are caught, logged, and swallowed — callers should not let one
    /// downstream's transient failure abort discovery for others.
    /// </summary>
    internal async Task RefreshToolsForPrefixAsync(string prefix, CancellationToken cancellationToken)
    {
        var config = _clientManager.GetConfigs().FirstOrDefault(c => c.Prefix == prefix);
        if (config is null) return;

        try
        {
            var client = await _clientManager.GetOrCreateClientAsync(prefix, cancellationToken);
            if (client is null) return;

            var tools = await client.ListToolsAsync(cancellationToken: cancellationToken);

            // N5: per-downstream allowlist filtering happens BEFORE policy is applied,
            // so a rejected tool's description is never even computed.
            var permitted = tools.Select(t => t.ProtocolTool).ToList();
            if (config.AllowedTools is { Count: > 0 } allow)
            {
                var allowSet = new HashSet<string>(allow, StringComparer.Ordinal);
                var rejected = permitted.Where(t => !allowSet.Contains(t.Name)).Select(t => t.Name).ToList();
                permitted = permitted.Where(t => allowSet.Contains(t.Name)).ToList();
                if (rejected.Count > 0)
                {
                    _logger.LogWarning(
                        "Rejecting {Count} unallowlisted tools from '{Name}': {Tools}",
                        rejected.Count, config.Name, string.Join(", ", rejected));
                }
            }

            // N5: provenance + schema policy applied to each tool.
            var sanitized = new List<ModelContextProtocol.Protocol.Tool>(permitted.Count);
            foreach (var t in permitted)
            {
                var policed = _toolPolicy.Apply(config.Prefix, t);
                if (policed is not null) sanitized.Add(policed);
            }

            // N6: compute diff vs current registered set BEFORE re-registering.
            var before = _toolRegistry.SnapshotForPrefix(config.Prefix);
            var afterNames = new HashSet<string>(sanitized.Select(s => s.Name), StringComparer.Ordinal);
            var beforeNames = new HashSet<string>(before.Keys, StringComparer.Ordinal);

            var added = afterNames.Except(beforeNames).ToList();
            var removed = beforeNames.Except(afterNames).ToList();
            var descChanged = new List<string>();
            foreach (var name in afterNames.Intersect(beforeNames))
            {
                var b = before[name].Tool;
                var a = sanitized.First(s => s.Name == name);
                if (!string.Equals(b.Description, a.Description, StringComparison.Ordinal))
                {
                    descChanged.Add(name);
                }
            }

            if (added.Count > 0 || removed.Count > 0 || descChanged.Count > 0)
            {
                _audit.ToolSetChanged(config.Prefix, added, removed, descChanged);
            }

            _toolRegistry.RegisterTools(config.Prefix, sanitized);

            _logger.LogDebug(
                "Discovered {Count} tools from '{Name}'",
                sanitized.Count, config.Name);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to discover tools from '{Name}'. Keeping cached tools.",
                config.Name);

            // Try to reconnect for next cycle. Skip the reconnect attempt for
            // lazy downstreams — there's no user context here, so the reconnect
            // would just trip the same OboExchangeException.
            if (!config.RequiresUserContext)
            {
                try { await _clientManager.ReconnectAsync(config.Prefix, cancellationToken); }
                catch { /* will retry next cycle */ }
            }
        }
    }
}
