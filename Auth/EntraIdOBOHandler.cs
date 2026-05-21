using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using EntraMcpProxy.Infrastructure;

namespace EntraMcpProxy.Auth;

/// <summary>
/// DelegatingHandler that performs On-Behalf-Of (OBO) token exchange when a user
/// principal is present in the current HTTP context, or falls back to a SP
/// app-only token (client_credentials) when explicitly running inside a
/// <see cref="DiscoveryContext.Enter"/> scope (startup tool discovery).
///
/// Security fixes in this version:
///   C1  — cache keyed on <see cref="OboCacheKey"/> (oid, tid, aud, scope from the
///           validated <see cref="ClaimsPrincipal"/>) instead of the previous
///           <c>string.GetHashCode()</c> of the raw assertion. 32-bit birthday
///           collisions at ~65 k entries can no longer leak one user's OBO token
///           to another user.
///   M14 — per-handler <see cref="PeriodicTimer"/> eviction loop removes expired
///           entries every minute; cache no longer grows without bound.
///   N2  — cache TTL is capped at 10 minutes regardless of what Entra's
///           <c>expires_in</c> field says (was 55 min, reduces revocation lag).
///   H7  — raw Entra error bodies are no longer included in exception messages;
///           they live only in <see cref="OboExchangeException.InnerEntraBody"/>
///           (consumed by DEBUG log only, never echoed to clients).
///   H6  — the silent SP fallback now requires an explicit
///           <see cref="DiscoveryContext.Enter"/> scope; any call path without a
///           user context that has not opted in receives a sanitised exception.
/// </summary>
public sealed class EntraIdOBOHandler : DelegatingHandler, IDisposable
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly HttpClient _tokenClient;
    private readonly string _tenantId;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly string _targetScope;
    private readonly string? _discoveryScope;
    private readonly string _tokenEndpointBaseUrl;
    private readonly ILogger<EntraIdOBOHandler> _logger;
    private readonly AuditLog? _audit;

    // C1: cache keyed on validated-claim composite, not raw token hash.
    private readonly ConcurrentDictionary<OboCacheKey, CacheEntry> _oboCache = new();

    // SP fallback cache (discovery path only).
    private (string Token, DateTimeOffset Expires)? _spTokenCache;
    private readonly SemaphoreSlim _spLock = new(1, 1);

    // M14: eviction loop tied to handler lifetime.
    private readonly CancellationTokenSource _evictionCts = new();

    // N2: hard cap on OBO token cache TTL.
    private static readonly TimeSpan MaxCacheTtl = TimeSpan.FromMinutes(10);

    // Advance expiry check margin: refresh when < 1 minute remains.
    private static readonly TimeSpan ExpiryMargin = TimeSpan.FromMinutes(1);

    /// <param name="tokenHandler">
    ///   Optional <see cref="HttpMessageHandler"/> for the internal token-endpoint
    ///   client. Pass a <c>FakeTokenHandler</c> in unit tests; leave <c>null</c>
    ///   in production (defaults to <see cref="HttpClientHandler"/>).
    /// </param>
    /// <param name="innerHandler">
    ///   Optional inner handler for the base <see cref="DelegatingHandler"/>
    ///   pipeline (downstream calls). Leave <c>null</c> in production.
    /// </param>
    /// <param name="egressEnforcer">
    ///   Optional <see cref="EgressEnforcingHandler"/> that wraps both the
    ///   downstream pipeline and the token-endpoint client. When non-null,
    ///   every outbound HTTP request (OBO downstream call + token exchange)
    ///   is checked against <see cref="EgressAllowlist"/> at send time.
    ///   Leave <c>null</c> in unit tests that supply their own stubs.
    ///   N19 runtime defense-in-depth.
    /// </param>
    public EntraIdOBOHandler(
        IHttpContextAccessor httpContextAccessor,
        string tenantId,
        string clientId,
        string clientSecret,
        string targetScope,
        ILogger<EntraIdOBOHandler> logger,
        HttpMessageHandler? tokenHandler = null,
        HttpMessageHandler? innerHandler = null,
        string? discoveryScope = null,
        string? tokenEndpointBaseUrl = null,
        AuditLog? audit = null,
        EgressEnforcingHandler? egressEnforcer = null)
        : base(WrapEgress(innerHandler ?? new HttpClientHandler(), egressEnforcer))
    {
        _httpContextAccessor = httpContextAccessor;
        _tenantId = tenantId;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _targetScope = targetScope;
        _discoveryScope = discoveryScope;
        _tokenEndpointBaseUrl = string.IsNullOrWhiteSpace(tokenEndpointBaseUrl)
            ? "https://login.microsoftonline.com"
            : tokenEndpointBaseUrl.TrimEnd('/');
        _logger = logger;
        _audit = audit;
        _tokenClient = new HttpClient(tokenHandler ?? new HttpClientHandler());

        // M14: start background eviction loop.
        _ = Task.Run(EvictionLoopAsync);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Best-effort: MCP session termination sends DELETE with no user context
        // (McpClient.DisposeAsync fires a DELETE outside any request scope).
        // When neither a bearer token nor a usable discovery scope is available,
        // skip auth attachment and let the downstream handle the unauthenticated
        // DELETE rather than throwing OboExchangeException and polluting logs with
        // spurious "shutdown failed" warnings on every clean client teardown.
        if (request.Method == HttpMethod.Delete)
        {
            var incomingTokenDel = GetIncomingBearerToken();
            if (string.IsNullOrEmpty(incomingTokenDel)
                && (!DiscoveryContext.IsActive || string.IsNullOrWhiteSpace(_discoveryScope)))
            {
                _logger.LogDebug(
                    "OBO: DELETE with no user context and no discovery scope — " +
                    "forwarding without auth (MCP session termination)");
                return await base.SendAsync(request, cancellationToken);
            }
        }

        var incomingToken = GetIncomingBearerToken();
        string token;

        if (string.IsNullOrEmpty(incomingToken))
        {
            // H6: SP fallback is only allowed inside an explicit discovery scope.
            if (!DiscoveryContext.IsActive)
            {
                throw new OboExchangeException(
                    "OBO requires a user context. " +
                    "Set DiscoveryContext.Enter() for SP-token paths (tool discovery).");
            }

            _logger.LogDebug("OBO: no user context — discovery scope active, using SP token");
            token = await GetSpTokenAsync(cancellationToken);
        }
        else
        {
            token = await GetOrExchangeOBOAsync(incomingToken, cancellationToken);
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, cancellationToken);
    }

    // ── token helpers ──────────────────────────────────────────────────────────

    private string? GetIncomingBearerToken()
    {
        var authHeader = _httpContextAccessor.HttpContext?
            .Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authHeader) ||
            !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return authHeader["Bearer ".Length..].Trim();
    }

    /// <summary>
    /// Builds a cache key from the validated <see cref="ClaimsPrincipal"/> in the
    /// current HTTP context. Throws <see cref="OboExchangeException"/> if the
    /// required <c>oid</c> or <c>tid</c> claims are absent — that indicates a
    /// misconfiguration in the upstream JWT validation pipeline.
    /// </summary>
    private OboCacheKey BuildCacheKey()
    {
        var principal = _httpContextAccessor.HttpContext?.User
            ?? throw new OboExchangeException(
                "OBO exchange requires an HTTP context with a validated user principal.");

        var oid = principal.FindFirst("oid")?.Value;
        var tid = principal.FindFirst("tid")?.Value;

        if (string.IsNullOrEmpty(oid) || string.IsNullOrEmpty(tid))
        {
            throw new OboExchangeException(
                "User principal missing required claims (oid, tid). " +
                "Ensure MapInboundClaims=false is set on the JWT bearer options.");
        }

        // aud and scope both point to the downstream resource identifier.
        return OboCacheKey.From(oid, tid, _targetScope, _targetScope);
    }

    private async Task<string> GetOrExchangeOBOAsync(
        string incomingToken, CancellationToken cancellationToken)
    {
        // C1: key derived from validated principal claims, not the raw token.
        var cacheKey = BuildCacheKey();

        if (_oboCache.TryGetValue(cacheKey, out var cached) &&
            cached.Expires > DateTimeOffset.UtcNow.Add(ExpiryMargin))
        {
            _logger.LogDebug("OBO: cache hit for {Key}", cacheKey);
            return cached.Token;
        }

        _logger.LogInformation("OBO: exchanging token for scope '{Scope}' key={Key}",
            _targetScope, cacheKey);

        var tokenEndpoint = $"{_tokenEndpointBaseUrl}/{_tenantId}/oauth2/v2.0/token";
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

        // N2: cap TTL at MaxCacheTtl (10 min) regardless of Entra's expires_in.
        var cappedTtl = TimeSpan.FromSeconds(Math.Min(expiresIn, (int)MaxCacheTtl.TotalSeconds));
        var expires = DateTimeOffset.UtcNow.Add(cappedTtl);
        _oboCache[cacheKey] = new CacheEntry(accessToken, expires);

        _logger.LogDebug("OBO: token obtained, TTL={Ttl}s (capped from {Raw}s)",
            (int)cappedTtl.TotalSeconds, expiresIn);
        return accessToken;
    }

    private async Task<string> GetSpTokenAsync(CancellationToken cancellationToken)
    {
        // Fast path (no lock): check if we have a fresh SP token already.
        if (_spTokenCache is { } sp &&
            sp.Expires > DateTimeOffset.UtcNow.Add(ExpiryMargin))
        {
            return sp.Token;
        }

        await _spLock.WaitAsync(cancellationToken);
        try
        {
            // Double-check inside the lock.
            if (_spTokenCache is { } sp2 &&
                sp2.Expires > DateTimeOffset.UtcNow.Add(ExpiryMargin))
            {
                return sp2.Token;
            }

            // N3: DiscoveryScope must be explicitly configured — null disables SP fallback.
            // The previous implementation used "{resource-id}/.default" which returns every
            // application permission consented on the SP. Too broad for a discovery-only path.
            if (string.IsNullOrWhiteSpace(_discoveryScope))
            {
                throw new OboExchangeException(
                    "Discovery SP path invoked but OBO:DiscoveryScope is not configured. " +
                    "Set DiscoveryScope to enable SP-token discovery, or disable downstream " +
                    "tool discovery in configuration.");
            }

            _logger.LogInformation(
                "OBO: discovery path — acquiring SP token (client_credentials) for scope '{Scope}'",
                _discoveryScope);

            var tokenEndpoint = $"{_tokenEndpointBaseUrl}/{_tenantId}/oauth2/v2.0/token";

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _clientId,
                ["client_secret"] = _clientSecret,
                ["scope"] = _discoveryScope,
            });

            var (token, expiresIn) = await PostTokenAsync(tokenEndpoint, content, cancellationToken);

            // N2: also cap the SP token TTL.
            var cappedTtl = TimeSpan.FromSeconds(Math.Min(expiresIn, (int)MaxCacheTtl.TotalSeconds));
            _spTokenCache = (token, DateTimeOffset.UtcNow.Add(cappedTtl));

            return token;
        }
        finally
        {
            _spLock.Release();
        }
    }

    /// <summary>
    /// Performs the HTTP POST to the Entra token endpoint and parses the response.
    ///
    /// H7: raw Entra error body is logged at DEBUG level only (it can contain AADSTS
    /// codes, tenant hints, or scope information that must not reach clients). The
    /// <see cref="OboExchangeException.Message"/> is intentionally generic.
    /// </summary>
    private async Task<(string Token, int ExpiresIn)> PostTokenAsync(
        string endpoint,
        FormUrlEncodedContent content,
        CancellationToken cancellationToken)
    {
        var response = await _tokenClient.PostAsync(endpoint, content, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("OBO: token request failed with status {Status}", response.StatusCode);
            // H7: body goes to DEBUG only — never to the exception Message.
            _logger.LogDebug("OBO: token failure body: {Body}", body);
            _audit?.OboExchangeFailed(
                user: _httpContextAccessor.HttpContext?.User,
                targetScope: _targetScope,
                error: $"HTTP {(int)response.StatusCode}");
            throw new OboExchangeException(
                $"OBO token exchange failed ({(int)response.StatusCode}).",
                innerEntraBody: body);
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var accessToken = root.GetProperty("access_token").GetString()
            ?? throw new OboExchangeException("Token response missing access_token.");

        var expiresIn = root.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;
        return (accessToken, expiresIn);
    }

    // ── eviction (M14) ────────────────────────────────────────────────────────

    private async Task EvictionLoopAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
            while (await timer.WaitForNextTickAsync(_evictionCts.Token))
            {
                EvictExpired(DateTimeOffset.UtcNow);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown path — suppress.
        }
    }

    /// <summary>
    /// Removes all OBO cache entries whose <see cref="CacheEntry.Expires"/> is at
    /// or before <paramref name="now"/>. Called by the background eviction loop
    /// and exposed <c>internal</c> for unit tests.
    /// </summary>
    internal void EvictExpired(DateTimeOffset now)
    {
        foreach (var kvp in _oboCache)
        {
            if (kvp.Value.Expires <= now)
                _oboCache.TryRemove(kvp.Key, out _);
        }
    }

    /// <summary>
    /// Returns the cached expiry for a given key, or <c>null</c> if the key is
    /// not in the cache. Exposed <c>internal</c> for unit tests (TTL cap assertion).
    /// </summary>
    internal DateTimeOffset? GetCacheExpiry(OboCacheKey key) =>
        _oboCache.TryGetValue(key, out var entry) ? entry.Expires : null;

    // ── egress wrapping (N19) ─────────────────────────────────────────────────

    /// <summary>
    /// Wraps <paramref name="inner"/> with the egress enforcer when one is
    /// provided. Each call to the constructor gets a fresh
    /// <see cref="EgressEnforcingHandler"/> instance (DelegatingHandler keeps
    /// an InnerHandler reference and is not shareable).
    /// </summary>
    private static HttpMessageHandler WrapEgress(
        HttpMessageHandler inner, EgressEnforcingHandler? enforcer)
    {
        if (enforcer is null) return inner;
        enforcer.InnerHandler = inner;
        return enforcer;
    }

    // ── lifecycle ─────────────────────────────────────────────────────────────

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _evictionCts.Cancel();
            _evictionCts.Dispose();
            _tokenClient.Dispose();
            _spLock.Dispose();
        }
        base.Dispose(disposing);
    }

    // ── inner types ───────────────────────────────────────────────────────────

    internal readonly record struct CacheEntry(string Token, DateTimeOffset Expires);
}
