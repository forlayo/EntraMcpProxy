namespace EntraMcpProxy.Services;

public class ToolAggregatorService : BackgroundService
{
    private readonly DownstreamClientManager _clientManager;
    private readonly ToolRegistry _toolRegistry;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ToolAggregatorService> _logger;

    public ToolAggregatorService(
        DownstreamClientManager clientManager,
        ToolRegistry toolRegistry,
        IConfiguration configuration,
        ILogger<ToolAggregatorService> logger)
    {
        _clientManager = clientManager;
        _toolRegistry = toolRegistry;
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial connection and discovery
        await _clientManager.ConnectAllAsync(stoppingToken);
        await DiscoverToolsAsync(stoppingToken);

        var intervalMinutes = _configuration.GetValue("Proxy:RefreshIntervalMinutes", 5);
        var interval = TimeSpan.FromMinutes(intervalMinutes);

        _logger.LogInformation("Tool aggregator started. Refresh interval: {Interval} minutes", intervalMinutes);

        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await DiscoverToolsAsync(stoppingToken);
        }
    }

    private async Task DiscoverToolsAsync(CancellationToken cancellationToken)
    {
        var configs = _clientManager.GetConfigs();
        var previousCount = _toolRegistry.Count;

        foreach (var config in configs)
        {
            try
            {
                var client = await _clientManager.GetOrCreateClientAsync(config.Prefix, cancellationToken);
                if (client is null) continue;

                var tools = await client.ListToolsAsync(cancellationToken: cancellationToken);
                var protocolTools = tools.Select(t => t.ProtocolTool).ToList();
                _toolRegistry.RegisterTools(config.Prefix, protocolTools);

                _logger.LogDebug(
                    "Discovered {Count} tools from '{Name}'",
                    protocolTools.Count, config.Name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to discover tools from '{Name}'. Keeping cached tools.",
                    config.Name);

                // Try to reconnect for next cycle
                try { await _clientManager.ReconnectAsync(config.Prefix, cancellationToken); }
                catch { /* will retry next cycle */ }
            }
        }

        if (_toolRegistry.Count != previousCount)
        {
            _logger.LogInformation(
                "Tool registry updated: {Count} total tools (was {Previous})",
                _toolRegistry.Count, previousCount);
        }
    }
}
