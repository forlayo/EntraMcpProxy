using EntraMcpProxy.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// Readiness health check: probes the Entra ID OIDC discovery document to verify
/// that the proxy can reach its upstream identity provider.
///
/// Tagged "ready" — contributes to /api/readyz but not /api/healthz (liveness).
/// A 5-second timeout is imposed so a slow/unreachable Entra does not hang the
/// readiness probe indefinitely.
/// </summary>
public sealed class EntraConnectivityHealthCheck : IHealthCheck
{
    private readonly IHttpClientFactory _factory;
    private readonly IOptions<EntraIdOptions> _entra;

    public EntraConnectivityHealthCheck(IHttpClientFactory factory, IOptions<EntraIdOptions> entra)
    {
        _factory = factory;
        _entra = entra;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Use the named entra-token-relay client (already has resilience + egress enforcement).
            using var http = _factory.CreateClient("entra-token-relay");
            http.Timeout = TimeSpan.FromSeconds(5);

            var authority = _entra.Value.Authority.TrimEnd('/');
            var url = $"{authority}/.well-known/openid-configuration";

            using var resp = await http.GetAsync(url, cancellationToken);

            return resp.IsSuccessStatusCode
                ? HealthCheckResult.Healthy($"Entra OIDC discovery reachable ({(int)resp.StatusCode})")
                : HealthCheckResult.Degraded($"Entra OIDC discovery returned {(int)resp.StatusCode}");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Entra OIDC discovery unreachable", ex);
        }
    }
}
