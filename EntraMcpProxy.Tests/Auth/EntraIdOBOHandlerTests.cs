using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EntraMcpProxy.Auth;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace EntraMcpProxy.Tests.Auth;

/// <summary>
/// Unit tests for <see cref="EntraIdOBOHandler"/>.
///
/// The handler is exercised by creating a minimal outer <see cref="HttpMessageHandler"/>
/// (FakeDownstreamHandler) chained via the DelegatingHandler pipeline so that
/// <c>base.SendAsync</c> completes normally. The token endpoint is intercepted by
/// the injected <see cref="FakeTokenHandler"/>.
/// </summary>
public class EntraIdOBOHandlerTests
{
    // ── helpers ──────────────────────────────────────────────────────────────

    private static IHttpContextAccessor PrincipalAccessor(
        string? oid,
        string? tid,
        string? rawBearer = "stub-incoming-jwt")
    {
        var claims = new List<Claim>();
        if (oid is not null) claims.Add(new Claim("oid", oid));
        if (tid is not null) claims.Add(new Claim("tid", tid));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));

        var ctx = new DefaultHttpContext { User = principal };
        if (rawBearer is not null)
            ctx.Request.Headers.Authorization = $"Bearer {rawBearer}";

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(ctx);
        return accessor;
    }

    private static IHttpContextAccessor EmptyAccessor()
    {
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);
        return accessor;
    }

    /// <summary>
    /// Builds a fully wired handler pipeline:
    ///   FakeDownstreamHandler (innermost) ← EntraIdOBOHandler ← (test sends to this)
    /// The <paramref name="fakeToken"/> intercepts calls to the Entra token endpoint.
    /// </summary>
    private static (EntraIdOBOHandler handler, FakeDownstreamHandler downstream)
        BuildPipeline(IHttpContextAccessor accessor, FakeTokenHandler fakeToken,
            string? discoveryScope = null)
    {
        var downstream = new FakeDownstreamHandler();
        var handler = new EntraIdOBOHandler(
            accessor,
            tenantId: "tenant-test",
            clientId: "client-test",
            clientSecret: "secret-test",
            targetScope: "api://resource/scope",
            logger: NullLogger<EntraIdOBOHandler>.Instance,
            tokenHandler: fakeToken,
            innerHandler: downstream,
            discoveryScope: discoveryScope);
        return (handler, downstream);
    }

    private static Task<HttpResponseMessage> SendAsync(EntraIdOBOHandler handler, CancellationToken ct = default)
    {
        var invoker = new HttpMessageInvoker(handler, disposeHandler: false);
        var req = new HttpRequestMessage(HttpMethod.Get, "http://downstream/tool");
        return invoker.SendAsync(req, ct);
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Two_users_get_separate_cache_entries()
    {
        // alice and bob have different oids → two separate OBO exchanges
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("alice-obo-token", expiresIn: 600);

        var aliceAccessor = PrincipalAccessor(oid: "alice-oid", tid: "T", rawBearer: "bearer-alice");
        var (handlerA, _) = BuildPipeline(aliceAccessor, tokenFake);

        await SendAsync(handlerA);               // exchange 1

        tokenFake.SetResponse("bob-obo-token", expiresIn: 600);
        var bobAccessor = PrincipalAccessor(oid: "bob-oid", tid: "T", rawBearer: "bearer-bob");

        // Same handler instance, different user context: swap accessor on next request
        // We simulate this by building a second handler (same shared cache is per-handler
        // and per-user — each handler has its own cache, so we just verify two distinct
        // calls happen for two distinct users on the same handler).
        // Rebuild with bob's accessor to simulate switching context:
        var bobFake = new FakeTokenHandler();
        bobFake.SetResponse("bob-obo-token", expiresIn: 600);
        var (handlerB, downB) = BuildPipeline(bobAccessor, bobFake);

        await SendAsync(handlerB);               // exchange 2

        // Both exchanges actually happened
        tokenFake.Received.Should().HaveCount(1, "alice got one exchange");
        bobFake.Received.Should().HaveCount(1, "bob got one exchange");

        // Downstream request headers differ
        downB.LastAuthHeader.Should().Contain("bob-obo-token");
    }

    [Fact]
    public async Task Same_user_within_TTL_uses_cached_token()
    {
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("cached-token", expiresIn: 600);

        var accessor = PrincipalAccessor(oid: "alice-oid", tid: "T");
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        await SendAsync(handler);   // miss — exchange happens
        await SendAsync(handler);   // hit  — no exchange

        tokenFake.Received.Should().HaveCount(1, "only one exchange for same user within TTL");
    }

    [Fact]
    public async Task Cache_entry_past_expiry_is_re_exchanged()
    {
        var tokenFake = new FakeTokenHandler();
        // expires_in=1 → but the cap makes it at most 1s here; we set 1 explicitly
        tokenFake.SetResponse("first-token", expiresIn: 1);

        var accessor = PrincipalAccessor(oid: "alice-oid", tid: "T");
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        await SendAsync(handler);                    // exchange 1

        // Manually evict the now-expired entry rather than sleeping
        handler.EvictExpired(DateTimeOffset.UtcNow.AddSeconds(2));

        tokenFake.SetResponse("second-token", expiresIn: 600);
        await SendAsync(handler);                    // exchange 2 (cache miss after eviction)

        tokenFake.Received.Should().HaveCount(2, "re-exchange happens after expiry");
    }

    [Fact]
    public async Task TTL_is_capped_at_10_minutes_even_if_entra_says_3600()
    {
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("long-token", expiresIn: 3600);   // 1 hour from Entra

        var accessor = PrincipalAccessor(oid: "alice-oid", tid: "T");
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        var before = DateTimeOffset.UtcNow;
        await SendAsync(handler);

        // Inspect the cache: expiry must be <= now + 10 min
        var maxAllowed = before.AddMinutes(10).AddSeconds(5);  // +5s buffer for test time
        var cacheExpiry = handler.GetCacheExpiry(
            OboCacheKey.From("alice-oid", "T", "api://resource/scope", "api://resource/scope"));

        cacheExpiry.Should().HaveValue();
        cacheExpiry!.Value.Should().BeBefore(maxAllowed,
            "TTL must be capped at 10 minutes regardless of Entra's expires_in");
    }

    [Fact]
    public async Task Missing_oid_claim_throws_OboExchangeException()
    {
        var tokenFake = new FakeTokenHandler();
        // tid present but oid missing
        var accessor = PrincipalAccessor(oid: null, tid: "T");
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        var act = () => SendAsync(handler);
        await act.Should().ThrowAsync<OboExchangeException>()
            .WithMessage("*missing required claims*");
    }

    [Fact]
    public async Task Entra_5xx_throws_OboExchangeException_with_generic_message()
    {
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetErrorResponse(
            HttpStatusCode.InternalServerError,
            body: """{"error":"server_error","error_description":"AADSTS90014: secret details"}""");

        var accessor = PrincipalAccessor(oid: "alice-oid", tid: "T");
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        var ex = await Assert.ThrowsAsync<OboExchangeException>(() => SendAsync(handler));

        ex.Message.Should().NotContain("AADSTS", "raw Entra body must NOT appear in Message");
        ex.Message.Should().NotContain("secret_details");
        ex.InnerEntraBody.Should().Contain("AADSTS90014",
            "raw Entra body IS present in InnerEntraBody for debug logging");
    }

    [Fact]
    public async Task Without_HttpContext_and_no_DiscoveryContext_throws()
    {
        var tokenFake = new FakeTokenHandler();
        var accessor = EmptyAccessor();             // no HttpContext at all
        var (handler, _) = BuildPipeline(accessor, tokenFake);

        var act = () => SendAsync(handler);
        await act.Should().ThrowAsync<OboExchangeException>()
            .WithMessage("*OBO requires a user context*");
    }

    [Fact]
    public async Task With_DiscoveryContext_Enter_uses_SP_token_with_explicit_DiscoveryScope()
    {
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("sp-discovery-token", expiresIn: 600);

        var accessor = EmptyAccessor();             // no user context
        var (handler, downstream) = BuildPipeline(accessor, tokenFake,
            discoveryScope: "api://x/Discovery.Tools");

        using (DiscoveryContext.Enter())
        {
            await SendAsync(handler);
        }

        // The token endpoint was called with client_credentials grant
        tokenFake.Received.Should().HaveCount(1);
        var body = await tokenFake.Received[0].Content!.ReadAsStringAsync();
        body.Should().Contain("client_credentials");
        body.Should().NotContain("jwt-bearer");

        // N3: the scope sent to Entra must be the explicit DiscoveryScope, not /.default
        body.Should().Contain("api%3A%2F%2Fx%2FDiscovery.Tools",
            "scope field must be URL-encoded form of 'api://x/Discovery.Tools'");
        body.Should().NotContain(".default",
            "the previous {resource-id}/.default broadened scope must no longer be sent");

        downstream.LastAuthHeader.Should().Contain("sp-discovery-token");
    }

    [Fact]
    public async Task Discovery_path_without_configured_DiscoveryScope_throws()
    {
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("should-not-be-used", expiresIn: 600);

        var accessor = EmptyAccessor();             // no user context
        // discoveryScope is null (omitted) — SP fallback is disabled
        var (handler, _) = BuildPipeline(accessor, tokenFake, discoveryScope: null);

        Func<Task> act = async () =>
        {
            using (DiscoveryContext.Enter())
            {
                await SendAsync(handler);
            }
        };

        await act.Should().ThrowAsync<OboExchangeException>()
            .WithMessage("*DiscoveryScope is not configured*");

        // No token requests should have reached the endpoint
        tokenFake.Received.Should().BeEmpty();
    }

    [Fact]
    public async Task Same_handler_two_users_produces_two_exchanges_with_distinct_assertions()
    {
        // The C1-closure proof: a single EntraIdOBOHandler instance, simulating the
        // production "singleton per downstream" architecture, is hit twice by two
        // different users via an IHttpContextAccessor that returns different
        // ClaimsPrincipals on consecutive calls. The FakeTokenHandler must record
        // TWO POSTs whose 'assertion' field values are the respective user tokens —
        // alice-token in POST 1, bob-token in POST 2.
        //
        // If the old GetHashCode()-keyed cache were still in place, a 32-bit
        // collision could return user A's OBO token to user B; with OboCacheKey-keyed
        // cache, two distinct oid claims guarantee two distinct cache entries and
        // therefore two distinct token exchanges.

        // Build two HttpContext instances — one per user.
        var aliceClaims = new List<Claim>
        {
            new("oid", "alice-oid"),
            new("tid", "tenant"),
        };
        var aliceCtx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(aliceClaims, "test")),
        };
        aliceCtx.Request.Headers.Authorization = "Bearer alice-token";

        var bobClaims = new List<Claim>
        {
            new("oid", "bob-oid"),
            new("tid", "tenant"),
        };
        var bobCtx = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(bobClaims, "test")),
        };
        bobCtx.Request.Headers.Authorization = "Bearer bob-token";

        // Single accessor whose HttpContext property returns a different context on
        // each access, simulating two sequential incoming requests.
        // The handler accesses HttpContext twice per SendAsync call (once for the
        // bearer header, once for the ClaimsPrincipal), so each context must be
        // enqueued twice.
        var contexts = new Queue<HttpContext>();
        contexts.Enqueue(aliceCtx);  // GetIncomingBearerToken
        contexts.Enqueue(aliceCtx);  // BuildCacheKey
        contexts.Enqueue(bobCtx);    // GetIncomingBearerToken
        contexts.Enqueue(bobCtx);    // BuildCacheKey
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(_ => contexts.Dequeue());

        // FakeTokenHandler always succeeds — we inspect the assertion field later.
        var tokenFake = new FakeTokenHandler();
        tokenFake.SetResponse("obo-token", expiresIn: 600);

        var downstream = new FakeDownstreamHandler();

        // Single handler instance — production "singleton per downstream" model.
        using var handler = new EntraIdOBOHandler(
            accessor,
            tenantId:     "tenant",
            clientId:     "client",
            clientSecret: "secret",
            targetScope:  "api://x/.default",
            logger:       NullLogger<EntraIdOBOHandler>.Instance,
            tokenHandler: tokenFake,
            innerHandler: downstream);

        using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);

        await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://downstream.test/probe"),
            CancellationToken.None);
        await invoker.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "https://downstream.test/probe"),
            CancellationToken.None);

        // C1 closure assertion: a single handler must NOT collapse alice and bob into
        // one cache entry — two separate OBO exchanges must have occurred.
        tokenFake.Received.Should().HaveCount(2,
            "single handler instance must produce two distinct OBO exchanges for two distinct users");

        var assertion1 = await ReadFormField(tokenFake.Received[0], "assertion");
        var assertion2 = await ReadFormField(tokenFake.Received[1], "assertion");
        assertion1.Should().Be("alice-token",
            "POST 1 must carry alice's incoming bearer as the OBO assertion");
        assertion2.Should().Be("bob-token",
            "POST 2 must carry bob's incoming bearer as the OBO assertion");
    }

    // Extracts a single URL-encoded form field from an HttpRequestMessage body.
    private static async Task<string?> ReadFormField(HttpRequestMessage req, string name)
    {
        var body = await req.Content!.ReadAsStringAsync();
        foreach (var kvp in body.Split('&'))
        {
            var eq = kvp.IndexOf('=');
            if (eq <= 0) continue;
            var k = System.Net.WebUtility.UrlDecode(kvp[..eq]);
            if (k != name) continue;
            return System.Net.WebUtility.UrlDecode(kvp[(eq + 1)..]);
        }
        return null;
    }

    // ── fake handlers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Intercepts calls to the Entra token endpoint made by <see cref="EntraIdOBOHandler"/>.
    /// </summary>
    internal sealed class FakeTokenHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Received { get; } = new();

        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string _body = DefaultBody("stub-obo", 3600);

        public void SetResponse(string token, int expiresIn)
        {
            _statusCode = HttpStatusCode.OK;
            _body = DefaultBody(token, expiresIn);
        }

        public void SetErrorResponse(HttpStatusCode code, string body)
        {
            _statusCode = code;
            _body = body;
        }

        private static string DefaultBody(string token, int expiresIn) =>
            $$"""{"access_token":"{{token}}","token_type":"Bearer","expires_in":{{expiresIn}}}""";

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Received.Add(request);
            var resp = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(resp);
        }
    }

    /// <summary>
    /// Sits at the innermost position in the handler pipeline and records the
    /// Authorization header that the OBO handler attached.
    /// </summary>
    internal sealed class FakeDownstreamHandler : HttpMessageHandler
    {
        public string? LastAuthHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            LastAuthHeader = request.Headers.Authorization?.ToString();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
