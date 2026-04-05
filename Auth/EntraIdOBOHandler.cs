using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;

namespace EntraMcpProxy.Auth;

/// <summary>
/// DelegatingHandler that uses OBO (On-Behalf-Of) when a user token is present in the
/// current HTTP context, or falls back to SP app-only token (client_credentials) when
/// running in background (e.g., startup tool discovery via tools/list).
/// </summary>
public class EntraIdOBOHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly HttpClient _tokenClient;
    private readonly string _tenantId;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly string _targetScope;
    private readonly ILogger<EntraIdOBOHandler> _logger;

    // Cache: token hash → (OBO token, expiry)
    private readonly ConcurrentDictionary<int, (string Token, DateTimeOffset Expires)> _oboCache = new();
    // Cache for SP fallback token
    private (string Token, DateTimeOffset Expires) _spTokenCache;
    private readonly SemaphoreSlim _spLock = new(1, 1);

    public EntraIdOBOHandler(
        IHttpContextAccessor httpContextAccessor,
        string tenantId,
        string clientId,
        string clientSecret,
        string targetScope,
        ILogger<EntraIdOBOHandler> logger)
        : base(new HttpClientHandler())
    {
        _httpContextAccessor = httpContextAccessor;
        _tenantId = tenantId;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _targetScope = targetScope;
        _logger = logger;
        _tokenClient = new HttpClient();
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var incomingToken = GetIncomingToken();

        try
        {
            string token;
            if (string.IsNullOrEmpty(incomingToken))
            {
                // No user context (background/startup) — use SP app-only token for tool discovery
                _logger.LogDebug("OBO: no user context — using SP fallback token for tool discovery");
                token = await GetSpTokenAsync(cancellationToken);
            }
            else
            {
                // User request — exchange via OBO
                token = await GetOrExchangeOBOAsync(incomingToken, cancellationToken);
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token acquisition failed for scope '{Scope}'", _targetScope);
            throw;
        }

        return await base.SendAsync(request, cancellationToken);
    }

    private string? GetIncomingToken()
    {
        var authHeader = _httpContextAccessor.HttpContext?
            .Request.Headers["Authorization"].ToString();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        return authHeader["Bearer ".Length..].Trim();
    }

    private async Task<string> GetOrExchangeOBOAsync(string incomingToken, CancellationToken cancellationToken)
    {
        var cacheKey = incomingToken.GetHashCode();

        if (_oboCache.TryGetValue(cacheKey, out var cached) &&
            cached.Expires > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            _logger.LogDebug("OBO: returning cached token for scope '{Scope}'", _targetScope);
            return cached.Token;
        }

        _logger.LogInformation("OBO: exchanging user token for scope '{Scope}'", _targetScope);

        var tokenEndpoint = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret,
            ["assertion"] = incomingToken,
            ["scope"] = _targetScope,
            ["requested_token_use"] = "on_behalf_of",
        });

        var (accessToken, expiresIn) = await PostTokenAsync(tokenEndpoint, content, cancellationToken);
        var expires = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
        _oboCache[cacheKey] = (accessToken, expires);

        _logger.LogDebug("OBO: token obtained, expires in {Seconds}s", expiresIn);
        return accessToken;
    }

    private async Task<string> GetSpTokenAsync(CancellationToken cancellationToken)
    {
        if (_spTokenCache.Token is not null &&
            _spTokenCache.Expires > DateTimeOffset.UtcNow.AddMinutes(5))
            return _spTokenCache.Token;

        await _spLock.WaitAsync(cancellationToken);
        try
        {
            // Double-check after lock
            if (_spTokenCache.Token is not null &&
                _spTokenCache.Expires > DateTimeOffset.UtcNow.AddMinutes(5))
                return _spTokenCache.Token;

            _logger.LogInformation("OBO: acquiring SP fallback token (client_credentials) for scope '{Scope}'", _targetScope);

            var tokenEndpoint = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";

            // Use .default scope for client_credentials (resource-level, not delegated scope)
            var resourceId = _targetScope.Contains('/') ? _targetScope[.._targetScope.IndexOf('/')] : _targetScope;
            var spScope = $"{resourceId}/.default";

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _clientId,
                ["client_secret"] = _clientSecret,
                ["scope"] = spScope,
            });

            var (accessToken, expiresIn) = await PostTokenAsync(tokenEndpoint, content, cancellationToken);
            _spTokenCache = (accessToken, DateTimeOffset.UtcNow.AddSeconds(expiresIn));

            return accessToken;
        }
        finally
        {
            _spLock.Release();
        }
    }

    private async Task<(string Token, int ExpiresIn)> PostTokenAsync(
        string endpoint, FormUrlEncodedContent content, CancellationToken cancellationToken)
    {
        var response = await _tokenClient.PostAsync(endpoint, content, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Token request failed: {Status} — {Body}", response.StatusCode, body);
            throw new InvalidOperationException($"Token request failed ({response.StatusCode}): {body}");
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var accessToken = root.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Token response missing access_token");

        var expiresIn = root.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;
        return (accessToken, expiresIn);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _tokenClient.Dispose();
            _spLock.Dispose();
        }
        base.Dispose(disposing);
    }
}
