using EntraMcpProxy.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Readiness health check: reports the connection status of configured downstream
/// MCP servers.
///
/// Tagged "ready" — contributes to /api/readyz but not /api/healthz (liveness).
///
/// Semantics:
/// - No downstream servers configured → Healthy (valid empty configuration).
/// - Downstream servers configured but none connected → Degraded (lazy-connect
///   on first user request — this is normal during startup; not a hard failure).
/// - At least one downstream connected → Healthy with a count summary.
/// </summary>
public sealed class DownstreamConnectivityHealthCheck : IHealthCheck
{
    private readonly DownstreamClientManager _clients;

    public DownstreamConnectivityHealthCheck(DownstreamClientManager clients) => _clients = clients;

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var configs = _clients.GetConfigs();
        var connected = _clients.GetAllClients().Count;

        if (configs.Count == 0)
        {
            return Task.FromResult(
                HealthCheckResult.Healthy("No downstream servers configured"));
        }

        if (connected == 0)
        {
            return Task.FromResult(
                HealthCheckResult.Degraded(
                    "No downstream servers connected (will lazy-connect on first user request)"));
        }

        return Task.FromResult(
            HealthCheckResult.Healthy(
                $"{connected}/{configs.Count} downstream(s) connected"));
    }
}
