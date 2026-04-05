using System.Net.Http.Headers;
using Azure.Core;
using Azure.Identity;

namespace EntraMcpProxy.Auth;

public class EntraIdTokenHandler : DelegatingHandler
{
    private readonly TokenCredential _credential;
    private readonly string[] _scopes;

    public EntraIdTokenHandler(string tenantId, string clientId, string clientSecret, string scope)
        : base(new HttpClientHandler())
    {
        _credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
        _scopes = [scope];
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var tokenResult = await _credential.GetTokenAsync(
            new TokenRequestContext(_scopes), cancellationToken);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResult.Token);

        return await base.SendAsync(request, cancellationToken);
    }
}
