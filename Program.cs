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

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using EntraMcpProxy.Services;

var builder = WebApplication.CreateBuilder(args);

// --- Authentication (Entra ID JWT — required) ---
var entraAuthority = builder.Configuration["EntraId:Authority"]
    ?? throw new InvalidOperationException("EntraId:Authority is required.");
var entraClientId = builder.Configuration["EntraId:ClientId"]
    ?? throw new InvalidOperationException("EntraId:ClientId is required.");
var entraTenantId = builder.Configuration["EntraId:TenantId"]
    ?? entraAuthority.Split('/').FirstOrDefault(s => s.Length == 36 && s.Contains('-'))
    ?? throw new InvalidOperationException("EntraId:TenantId could not be resolved from Authority.");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = entraAuthority;
        options.RequireHttpsMetadata = builder.Configuration.GetValue("EntraId:RequireHttpsMetadata", true);
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidAudiences = new[]
        {
            entraClientId,
            $"api://{entraClientId}",
        };
        // Accept both v1.0 (sts.windows.net) and v2.0 issuers — access tokens for
        // custom API scopes (api://...) are issued as v1.0 even via the v2.0 endpoint.
        options.TokenValidationParameters.ValidIssuers = new[]
        {
            $"https://sts.windows.net/{entraTenantId}/",
            $"https://login.microsoftonline.com/{entraTenantId}/v2.0",
            $"https://login.microsoftonline.com/{entraTenantId}/",
        };
    });
builder.Services.AddAuthorization();

builder.Services.AddHttpContextAccessor();

// --- Downstream configuration ---
builder.Services.Configure<List<DownstreamServerOptions>>(
    builder.Configuration.GetSection("DownstreamServers"));

// --- Services ---
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
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var app = builder.Build();

// Trust X-Forwarded-Proto/Host from ingress (e.g. AKS terminates TLS, forwards http internally)
var forwardedOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};
forwardedOptions.KnownIPNetworks.Clear();
forwardedOptions.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedOptions);

app.UseExceptionHandler();
app.UseCors();
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
app.MapGet("/.well-known/openid-configuration", (HttpContext context) =>
{
    var scheme = context.Request.Scheme;
    var host = context.Request.Host;
    var baseUrl = $"{scheme}://{host}";
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

app.MapGet("/authorize", (HttpContext context) =>
{
    var q = context.Request.Query;
    var entraAuthorize = $"https://login.microsoftonline.com/{entraTenantId}/oauth2/v2.0/authorize";
    var qs = new Dictionary<string, string?>
    {
        ["response_type"]         = q["response_type"].ToString() is { Length: > 0 } rt ? rt : "code",
        ["client_id"]             = entraClientId,
        ["redirect_uri"]          = q["redirect_uri"],
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

app.MapPost("/token", async (HttpContext context) =>
{
    var tokenEndpoint = $"https://login.microsoftonline.com/{entraTenantId}/oauth2/v2.0/token";
    var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
    using var http = new HttpClient();
    var resp = await http.SendAsync(new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
    {
        Content = new StringContent(body, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded"),
    });
    var respBody = await resp.Content.ReadAsStringAsync();
    context.Response.StatusCode = (int)resp.StatusCode;
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(respBody);
});

// RFC 9728 — Protected Resource Metadata
app.MapGet("/.well-known/oauth-protected-resource", (HttpContext context) =>
{
    var scheme = context.Request.Scheme;
    var host = context.Request.Host;
    var baseUrl = $"{scheme}://{host}";

    return Results.Json(new
    {
        resource = $"api://{entraClientId}",
        authorization_servers = new[] { baseUrl },
        bearer_methods_supported = new[] { "header" },
        scopes_supported = new[] { "openid", "profile", "offline_access", $"api://{entraClientId}/user_impersonation" },
    });
});

// Auth middleware for MCP endpoints — all routes except the public ones require a valid bearer token.
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
        var scheme = context.Request.Scheme;
        var host = context.Request.Host;
        context.Response.StatusCode = 401;
        context.Response.Headers["WWW-Authenticate"] =
            $"Bearer resource_metadata=\"{scheme}://{host}/.well-known/oauth-protected-resource\"";
        return;
    }

    await next();
});

app.MapMcp();
app.Run();

// Marker for Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>.
public partial class Program { }
