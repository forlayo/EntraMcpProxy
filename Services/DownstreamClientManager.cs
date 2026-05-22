using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Client;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;

namespace EntraMcpProxy.Services;

public class DownstreamClientManager : IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, McpClient> _clients = new();
    // Per-prefix lock to serialize concurrent connect attempts from request paths
    // (e.g., two users hitting list_tools at cold start for a lazy downstream).
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _connectLocks = new();
    private readonly IReadOnlyList<DownstreamServerOptions> _configs;
    protected readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<DownstreamClientManager> _logger;
    protected readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AuditLog _audit;
    private readonly IServiceProvider _serviceProvider;
    private readonly IHttpClientFactory _httpClientFactory;

    public DownstreamClientManager(
        IOptions<List<DownstreamServerOptions>> configs,
        ILoggerFactory loggerFactory,
        IHttpContextAccessor httpContextAccessor,
        AuditLog audit,
        IServiceProvider serviceProvider,
        IHttpClientFactory httpClientFactory)
    {
        _configs = configs.Value.Where(c => c.Enabled && !string.IsNullOrWhiteSpace(c.BaseUrl)).ToList();
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<DownstreamClientManager>();
        _httpContextAccessor = httpContextAccessor;
        _audit = audit;
        _serviceProvider = serviceProvider;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<McpClient?> GetOrCreateClientAsync(string prefix, CancellationToken cancellationToken = default)
    {
        if (_clients.TryGetValue(prefix, out var existing))
            return existing;

        var config = _configs.FirstOrDefault(c => c.Prefix == prefix);
        if (config is null)
            return null;

        return await ConnectAsync(config, cancellationToken);
    }

    public async Task ConnectAllAsync(CancellationToken cancellationToken = default)
    {
        foreach (var config in _configs)
        {
            if (config.RequiresUserContext)
            {
                _logger.LogInformation(
                    "Skipping eager connect for downstream '{Name}' " +
                    "(OBOToken without DiscoveryScope — will connect on first user request)",
                    config.Name);
                continue;
            }

            try
            {
                await ConnectAsync(config, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to connect to downstream '{Name}' at {BaseUrl}",
                    config.Name, config.BaseUrl);
            }
        }
    }

    public McpClient? GetClient(string prefix) =>
        _clients.TryGetValue(prefix, out var client) ? client : null;

    // Virtual to allow test subclasses to simulate connection state without
    // real McpClient instances (used by DownstreamConnectivityHealthCheck tests).
    public virtual IReadOnlyList<(string Prefix, McpClient Client)> GetAllClients() =>
        _clients.Select(kvp => (kvp.Key, kvp.Value)).ToList();

    public IReadOnlyList<DownstreamServerOptions> GetConfigs() => _configs;

    private async Task<McpClient> ConnectAsync(DownstreamServerOptions config, CancellationToken cancellationToken)
    {
        // Serialize per-prefix so that two concurrent request paths hitting cold
        // start for the same downstream do not both build (and leak) an McpClient.
        var sem = _connectLocks.GetOrAdd(config.Prefix, _ => new SemaphoreSlim(1, 1));
        await sem.WaitAsync(cancellationToken);
        try
        {
            if (_clients.TryGetValue(config.Prefix, out var existing))
                return existing;

            var httpClient = CreateHttpClient(config);

            var transportOptions = new HttpClientTransportOptions
            {
                Endpoint = new Uri(config.BaseUrl),
            };

            var transport = new HttpClientTransport(transportOptions, httpClient, _loggerFactory, ownsHttpClient: true);

            var clientOptions = new McpClientOptions
            {
                ClientInfo = new() { Name = "EntraMcpProxy", Version = "1.0.0" },
            };

            var client = await McpClient.CreateAsync(transport, clientOptions, _loggerFactory, cancellationToken);
            _clients[config.Prefix] = client;

            _logger.LogInformation(
                "Connected to downstream '{Name}' at {BaseUrl} (auth: {AuthType})",
                config.Name, config.BaseUrl, config.AuthType);
            return client;
        }
        finally
        {
            sem.Release();
        }
    }

    protected virtual HttpClient CreateHttpClient(DownstreamServerOptions config)
    {
        if (string.Equals(config.AuthType, "EntraId", StringComparison.OrdinalIgnoreCase))
        {
            var entra = config.EntraId
                ?? throw new InvalidOperationException(
                    $"Downstream '{config.Name}' uses EntraId auth but has no EntraId config.");

            var handler = new EntraIdTokenHandler(
                entra.TenantId, entra.ClientId, entra.ClientSecret, entra.Scope);

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds)
            };
        }

        if (string.Equals(config.AuthType, "OBOToken", StringComparison.OrdinalIgnoreCase))
        {
            var obo = config.OBO
                ?? throw new InvalidOperationException(
                    $"Downstream '{config.Name}' uses OBOToken auth but has no OBO config.");

            var oboLogger = _loggerFactory.CreateLogger<EntraIdOBOHandler>();

            // N19: resolve a fresh EgressEnforcingHandler for each OBO handler
            // (DelegatingHandler stores an InnerHandler reference; it must not be
            // shared between multiple consumers).
            var egressEnforcer = _serviceProvider.GetRequiredService<EgressEnforcingHandler>();

            var handler = new EntraIdOBOHandler(
                _httpContextAccessor,
                obo.TenantId, obo.ClientId, obo.ClientSecret, obo.TargetScope,
                oboLogger,
                discoveryScope: obo.DiscoveryScope,
                tokenEndpointBaseUrl: obo.TokenEndpointBaseUrl,
                audit: _audit,
                egressEnforcer: egressEnforcer,
                tokenClientFactory: _httpClientFactory);

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds)
            };
        }

        // Default: ApiKey auth
        var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds) };

        if (!string.IsNullOrWhiteSpace(config.ApiKey))
            httpClient.DefaultRequestHeaders.Add("X-API-Key", config.ApiKey);

        return httpClient;
    }

    public async Task ReconnectAsync(string prefix, CancellationToken cancellationToken = default)
    {
        if (_clients.TryRemove(prefix, out var old))
            await old.DisposeAsync();

        var config = _configs.FirstOrDefault(c => c.Prefix == prefix);
        if (config is not null)
            await ConnectAsync(config, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var client in _clients.Values)
        {
            try { await client.DisposeAsync(); }
            catch { /* best effort */ }
        }
        _clients.Clear();

        foreach (var sem in _connectLocks.Values)
        {
            sem.Dispose();
        }
        _connectLocks.Clear();
    }
}
