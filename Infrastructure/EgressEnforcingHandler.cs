using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace EntraMcpProxy.Infrastructure;

/// <summary>
/// DelegatingHandler that fails outbound requests whose target host is not
/// in <see cref="EgressAllowlist"/>. Sits at the outermost position of
/// the HTTP pipeline used by EntraIdOBOHandler (and any other downstream
/// HttpClient).
///
/// Finding N19 runtime enforcement.
/// </summary>
public sealed class EgressEnforcingHandler : DelegatingHandler
{
    private readonly EgressAllowlist _allowlist;
    private readonly ILogger<EgressEnforcingHandler> _logger;

    public EgressEnforcingHandler(EgressAllowlist allowlist, ILogger<EgressEnforcingHandler> logger)
    {
        _allowlist = allowlist;
        _logger = logger;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var host = request.RequestUri?.Host ?? "";
        if (!_allowlist.IsAllowed(host))
        {
            _logger.LogError(
                "Egress blocked: outbound request to '{Host}' is not in Proxy:EgressAllowlist",
                host);
            throw new HttpRequestException(
                $"Egress to '{host}' is not permitted by the configured allowlist.");
        }
        return base.SendAsync(request, cancellationToken);
    }
}
