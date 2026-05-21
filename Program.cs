// EntraMcpProxy — Application entry point.
//
// Bootstraps the ASP.NET Core host with three responsibilities:
//   1. OAuth AS facade  — /authorize, /token, and /.well-known/openid-configuration redirect
//      Claude Web through Entra ID (Azure AD) without requiring dynamic client registration.
//   2. RFC 9728        — /.well-known/oauth-protected-resource advertises this proxy as the
//      authorization server so MCP clients can discover the correct auth flow.
//   3. MCP aggregator  — a single SSE endpoint aggregates tools from all configured downstream
//      MCP servers, namespaced by prefix (e.g. azdevops__*, internal__*).
//
// Entra ID configuration (EntraId:Authority, EntraId:ClientId, EntraId:TenantId) is required.
// The application will throw on startup if any of these values are missing.

using System;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using EntraMcpProxy.Services;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration binding + startup validation ---
//
// All three Options types are registered with ValidateOnStart so any
// misconfiguration fails the host build before the first request arrives
// (OptionsValidationException is thrown during IHost.StartAsync which
// WebApplicationFactory runs as part of CreateClient / server startup).
// Validators are registered as singletons so IOptions<T> resolution
// triggers them.

builder.Services.AddOptions<EntraIdOptions>()
    .Bind(builder.Configuration.GetSection("EntraId"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<EntraIdOptions>, EntraIdOptionsValidator>();

builder.Services.AddOptions<ProxyOptions>()
    .Bind(builder.Configuration.GetSection("Proxy"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<ProxyOptions>, ProxyOptionsValidator>();

builder.Services.AddOptions<List<DownstreamServerOptions>>()
    .Bind(builder.Configuration.GetSection("DownstreamServers"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<List<DownstreamServerOptions>>, DownstreamServerOptionsValidator>();

// Pull the raw config values needed for the existing code paths below
// (authority, client-id, tenant-id).  Using builder.Configuration[...] here
// is intentional — these values are already validated by the Options layer
// above, so the only path where they are empty is a misconfiguration that
// ValidateOnStart will catch before any request is processed.
var entraAuthority = builder.Configuration["EntraId:Authority"] ?? "";
var entraClientId  = builder.Configuration["EntraId:ClientId"]  ?? "";
var entraTenantId  = builder.Configuration["EntraId:TenantId"]  ?? "";

// --- Authentication (Entra ID JWT — required) ---
//
// NOTE: JwtBearerOptions MUST be configured via IConfigureOptions<> with IConfiguration
// injected at runtime rather than capturing builder.Configuration values at registration
// time.  When WebApplicationFactory overrides configuration (e.g. to point at FakeEntra
// for integration tests), builder.Configuration is not yet updated with the override at
// the moment AddJwtBearer runs — the DI-resolved IConfiguration IS correct at first use.

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

// Configure JwtBearerOptions via DI-resolved IConfiguration so WebApplicationFactory
// config overrides (EntraId:Authority / TenantId / ClientId) take effect in tests.
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IConfiguration>((options, config) =>
    {
        var authority = config["EntraId:Authority"] ?? "";
        var clientId  = config["EntraId:ClientId"]  ?? "";
        var tenantId  = config["EntraId:TenantId"]  ?? "";

        options.Authority = authority;
        options.RequireHttpsMetadata = config.GetValue("EntraId:RequireHttpsMetadata", true);

        // Phase 7 prerequisite: do not rewrite "oid" → long Microsoft URI.
        // EntraIdOBOHandler (Phase 7) keys the OBO cache on User.FindFirst("oid").
        // With the default MapInboundClaims=true, JwtBearerHandler rewrites "oid"
        // to the long URI before populating ClaimsPrincipal, so FindFirst("oid")
        // returns null in production while tests using MapInboundClaims=false pass.
        options.MapInboundClaims = false;

        // N13/L17: every TokenValidationParameters flag set explicitly — a future
        // maintainer cannot silently weaken validation without removing a named line.
        var p = options.TokenValidationParameters;
        p.ValidateIssuer           = true;
        p.ValidateAudience         = true;
        p.ValidateLifetime         = true;
        p.ValidateIssuerSigningKey = true;
        p.RequireSignedTokens      = true;
        p.RequireExpirationTime    = true;
        p.SaveSigninToken          = false;
        p.ClockSkew                = TimeSpan.FromMinutes(2);

        p.ValidAudiences = new[]
        {
            clientId,
            $"api://{clientId}",
        };

        // Accept both v1.0 (sts.windows.net) and v2.0 issuers — access tokens for
        // custom API scopes (api://...) are issued as v1.0 even via the v2.0 endpoint.
        // authority is explicitly included so FakeEntra integration tests validate
        // cleanly against the dynamic WireMock URL (and to make the mapping explicit in
        // production even though it is a subset of the two login.microsoftonline.com entries).
        p.ValidIssuers = new[]
        {
            $"https://sts.windows.net/{tenantId}/",
            $"https://login.microsoftonline.com/{tenantId}/v2.0",
            $"https://login.microsoftonline.com/{tenantId}/",
            authority, // explicit: covers FakeEntra in tests; in prod same as v2.0 entry above
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddHttpContextAccessor();

// --- Services ---
builder.Services.AddSingleton<IPublicBaseUrlAccessor, PublicBaseUrlAccessor>();
builder.Services.AddSingleton<IRedirectUriValidator, RedirectUriValidator>();
builder.Services.AddSingleton<PkceValidator>();
builder.Services.AddSingleton<ToolRegistry>();
builder.Services.AddSingleton<DownstreamClientManager>();
builder.Services.AddSingleton<ProxyToolHandler>();
builder.Services.AddHostedService<ToolAggregatorService>();

// --- MCP Server with dynamic handlers ---
builder.Services.AddMcpServer(options =>
{
    options.ServerInfo = new() { Name = "EntraMcpProxy", Version = "1.0.0" };
    options.Capabilities = new()
    {
        Tools = new() { ListChanged = true },
    };
})
.WithHttpTransport()
.WithListToolsHandler((request, ct) =>
{
    var handler = request.Server.Services!.GetRequiredService<ProxyToolHandler>();
    return handler.HandleListToolsAsync(request, ct);
})
.WithCallToolHandler((request, ct) =>
{
    var handler = request.Server.Services!.GetRequiredService<ProxyToolHandler>();
    return handler.HandleCallToolAsync(request, ct);
});

builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
    {
        var origins = builder.Configuration.GetSection("Proxy:AllowedCorsOrigins").Get<string[]>()
                      ?? System.Array.Empty<string>();
        if (origins.Length > 0)
        {
            policy.WithOrigins(origins)
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        }
        // If empty: do not call WithOrigins — the policy is effectively closed.
        // (ASP.NET Core CORS middleware will not emit Access-Control-Allow-Origin
        // when no origins are configured for the request.)
    }));

// M9: Use named HttpClient for the /token relay to Entra, managed by IHttpClientFactory.
builder.Services.AddHttpClient("entra-token-relay");

// M10: Per-IP fixed-window rate limit on the OAuth facade endpoints.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        // Only apply to /authorize and /token. Other paths get an unlimited bucket.
        var path = ctx.Request.Path.Value ?? "";
        bool gated = path.StartsWith("/authorize", StringComparison.OrdinalIgnoreCase)
                  || path.StartsWith("/token",     StringComparison.OrdinalIgnoreCase);
        if (!gated)
        {
            return RateLimitPartition.GetNoLimiter("ungated");
        }

        // Per-IP partition; falls back to "anonymous" if RemoteIpAddress is unavailable.
        string key = ctx.Connection.RemoteIpAddress?.ToString() ?? "anonymous";

        var perMinute = ctx.RequestServices
            .GetRequiredService<IOptions<ProxyOptions>>()
            .Value.RateLimit.RequestsPerMinute;

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"{path}|{key}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = perMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true,
            });
    });
});

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var app = builder.Build();

// --- Prod-config startup guard (finding N18) ---
// Reject the dangerous combination of Production environment + disabled HTTPS
// metadata validation.  The validators above accept RequireHttpsMetadata=false
// as a valid value (it is needed for local dev/staging); this guard adds the
// environment dimension that a pure IValidateOptions cannot see.
// Placed after Build() so WebApplicationFactory test overrides (env, config)
// are fully applied before the check runs.
if (app.Environment.IsProduction())
{
    var entraId = app.Services.GetRequiredService<IOptions<EntraIdOptions>>().Value;
    if (!entraId.RequireHttpsMetadata)
    {
        throw new InvalidOperationException(
            "EntraId:RequireHttpsMetadata=false is not allowed in Production. " +
            "Set it to true, or run with a non-Production ASPNETCORE_ENVIRONMENT.");
    }
}

app.UseExceptionHandler();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Health check — exempt from auth
app.MapGet("/api/healthz", () => Results.Ok(new
{
    status = "Healthy",
    timestamp = DateTime.UtcNow,
}));

// OAuth AS facade — Claude Web constructs {mcp_url}/authorize and {mcp_url}/token
// directly when configured with client_id+secret, so the proxy must expose these.
app.MapGet("/.well-known/openid-configuration", (IPublicBaseUrlAccessor accessor) =>
{
    var baseUrl = accessor.Get();
    return Results.Json(new
    {
        issuer = baseUrl,
        authorization_endpoint = $"{baseUrl}/authorize",
        token_endpoint = $"{baseUrl}/token",
        response_types_supported = new[] { "code" },
        grant_types_supported = new[] { "authorization_code" },
        code_challenge_methods_supported = new[] { "S256" },
        scopes_supported = new[] { "openid", "profile", "offline_access", $"api://{entraClientId}/user_impersonation" },
    });
});

app.MapGet("/authorize", (HttpContext context, IRedirectUriValidator redirectValidator, PkceValidator pkceValidator) =>
{
    var q = context.Request.Query;

    // H3: reject unlisted / malformed redirect_uri before any forwarding.
    var redirectUri = q["redirect_uri"].ToString();
    if (!redirectValidator.IsAllowed(redirectUri))
    {
        return Results.BadRequest(new
        {
            error = "invalid_request",
            error_description = "redirect_uri is not in the allowlist.",
        });
    }

    // H4: PKCE is mandatory at the proxy level. The discovery doc advertises S256
    // — clients MUST send code_challenge with code_challenge_method=S256.
    var pkce = pkceValidator.Validate(
        challenge: q["code_challenge"],
        method:    q["code_challenge_method"]);
    if (!pkce.IsValid)
    {
        return Results.BadRequest(new
        {
            error = "invalid_request",
            error_description = pkce.Error,
        });
    }

    var entraAuthorize = $"https://login.microsoftonline.com/{entraTenantId}/oauth2/v2.0/authorize";
    var qs = new Dictionary<string, string?>
    {
        ["response_type"]         = q["response_type"].ToString() is { Length: > 0 } rt ? rt : "code",
        ["client_id"]             = entraClientId,
        ["redirect_uri"]          = redirectUri,
        ["scope"]                 = $"openid profile offline_access api://{entraClientId}/user_impersonation",
        ["state"]                 = q["state"],
        ["code_challenge"]        = q["code_challenge"],
        ["code_challenge_method"] = q["code_challenge_method"],
    };
    var queryString = string.Join("&", qs
        .Where(kv => !string.IsNullOrEmpty(kv.Value))
        .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}"));
    return Results.Redirect($"{entraAuthorize}?{queryString}");
});

app.MapPost("/token", async (HttpContext context, IHttpClientFactory httpFactory) =>
{
    // M13: reject oversized bodies before reading them all into memory.
    const int MaxBodyBytes = 8 * 1024;
    if (context.Request.ContentLength is long len && len > MaxBodyBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        return;
    }

    // Even without Content-Length, cap how much we'll read.
    using var reader = new StreamReader(context.Request.Body);
    var buffer = new char[MaxBodyBytes + 1];
    int total = 0;
    while (total <= MaxBodyBytes)
    {
        int n = await reader.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
        if (n == 0) break;
        total += n;
    }
    if (total > MaxBodyBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        return;
    }
    var body = new string(buffer, 0, total);

    // M9: managed HttpClient lifecycle.
    var http = httpFactory.CreateClient("entra-token-relay");
    var tokenEndpoint = $"https://login.microsoftonline.com/{entraTenantId}/oauth2/v2.0/token";
    var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
    {
        Content = new StringContent(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"),
    };
    var resp = await http.SendAsync(req);
    var respBody = await resp.Content.ReadAsStringAsync();
    context.Response.StatusCode = (int)resp.StatusCode;
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(respBody);
});

// RFC 9728 — Protected Resource Metadata
app.MapGet("/.well-known/oauth-protected-resource", (IPublicBaseUrlAccessor accessor) =>
{
    var baseUrl = accessor.Get();
    return Results.Json(new
    {
        resource = $"api://{entraClientId}",
        authorization_servers = new[] { baseUrl },
        bearer_methods_supported = new[] { "header" },
        scopes_supported = new[] { "openid", "profile", "offline_access", $"api://{entraClientId}/user_impersonation" },
    });
});

// Auth middleware for MCP endpoints — all routes except the public ones require a valid bearer token.
// Resolve the accessor once at registration time (it is a singleton backed by IOptions<ProxyOptions>).
var publicBaseUrl = app.Services.GetRequiredService<IPublicBaseUrlAccessor>();

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/healthz") ||
        context.Request.Path.StartsWithSegments("/.well-known") ||
        context.Request.Path.StartsWithSegments("/authorize") ||
        context.Request.Path.StartsWithSegments("/token"))
    {
        await next();
        return;
    }

    // Require authenticated user — return RFC 9728 compliant 401
    if (context.User.Identity?.IsAuthenticated != true)
    {
        context.Response.StatusCode = 401;
        context.Response.Headers["WWW-Authenticate"] =
            $"Bearer resource_metadata=\"{publicBaseUrl.Get()}/.well-known/oauth-protected-resource\"";
        return;
    }

    await next();
});

app.MapMcp();
app.Run();

// Marker for Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>.
public partial class Program { }
