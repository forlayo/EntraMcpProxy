using System.Linq;
using System.Security.Claims;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
using EntraMcpProxy.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace EntraMcpProxy.Services;

public class ProxyToolHandler
{
    private readonly ToolRegistry _toolRegistry;
    private readonly DownstreamClientManager _clientManager;
    private readonly ToolResultWrapper _wrapper;
    private readonly DownstreamAuthorizationFilter _authz;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ProxyToolHandler> _logger;
    private readonly AuditLog _audit;

    public ProxyToolHandler(
        ToolRegistry toolRegistry,
        DownstreamClientManager clientManager,
        ToolResultWrapper wrapper,
        DownstreamAuthorizationFilter authz,
        IHttpContextAccessor httpContextAccessor,
        ILogger<ProxyToolHandler> logger,
        AuditLog audit)
    {
        _toolRegistry = toolRegistry;
        _clientManager = clientManager;
        _wrapper = wrapper;
        _authz = authz;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _audit = audit;
    }

    public ValueTask<ListToolsResult> HandleListToolsAsync(
        RequestContext<ListToolsRequestParams> request,
        CancellationToken cancellationToken)
    {
        var user = _httpContextAccessor.HttpContext?.User
            ?? new ClaimsPrincipal(new ClaimsIdentity());

        var allTools = _toolRegistry.GetAllTools();
        var visible = allTools.Where(t => _authz.IsAllowed(user, t.Name)).ToList();

        _logger.LogDebug("ListTools: {Total} tools total, {Visible} visible to user", allTools.Count, visible.Count);
        return new ValueTask<ListToolsResult>(new ListToolsResult { Tools = visible });
    }

    public async ValueTask<CallToolResult> HandleCallToolAsync(
        RequestContext<CallToolRequestParams> request,
        CancellationToken cancellationToken)
    {
        var toolName = request.Params?.Name
            ?? throw new McpException("Tool name is required");

        var user = _httpContextAccessor.HttpContext?.User
            ?? new ClaimsPrincipal(new ClaimsIdentity());

        if (!_authz.IsAllowed(user, toolName))
        {
            _audit.AuthzDenied(user, toolName, reason: "not in allowed groups");
            throw new McpException($"Not authorized to call tool '{toolName}'");
        }

        var entry = _toolRegistry.TryResolve(toolName);
        if (entry is null)
            throw new McpException($"Unknown tool: '{toolName}'");

        var client = _clientManager.GetClient(entry.Prefix);
        if (client is null)
            throw new McpException($"Downstream server '{entry.Prefix}' is not connected");

        _logger.LogInformation(
            "Routing '{PrefixedName}' → '{Prefix}':'{OriginalName}'",
            toolName, entry.Prefix, entry.OriginalName);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var correlationId = System.Guid.NewGuid().ToString();

        var downstreamParams = new CallToolRequestParams
        {
            Name = entry.OriginalName,
            Arguments = request.Params?.Arguments,
        };

        try
        {
            var result = await client.CallToolAsync(downstreamParams, cancellationToken);
            sw.Stop();

            _audit.ToolInvocation(
                user,
                tool: toolName,
                args: request.Params?.Arguments,
                status: result.IsError == true ? "error" : "success",
                latencyMs: sw.ElapsedMilliseconds,
                correlationId: correlationId);

            if (result.IsError == true)
            {
                // N17: log only the count, never the content (may contain PII or attacker payloads).
                _logger.LogWarning(
                    "Downstream '{Prefix}':'{Tool}' returned isError=true. ContentBlocks={Count}",
                    entry.Prefix, entry.OriginalName, result.Content.Count);
            }
            else
            {
                _logger.LogDebug(
                    "Downstream '{Prefix}':'{Tool}' returned {ContentCount} content blocks",
                    entry.Prefix, entry.OriginalName, result.Content.Count);
            }

            // N11 + N12: wrap each text block in provenance tags; enforce size cap.
            return _wrapper.Wrap(result, entry.Prefix, entry.OriginalName);
        }
        catch (Exception ex)
        {
            sw.Stop();
            _audit.ToolInvocation(
                user,
                tool: toolName,
                args: request.Params?.Arguments,
                status: "exception",
                latencyMs: sw.ElapsedMilliseconds,
                correlationId: correlationId);
            _logger.LogError(ex,
                "Downstream '{Prefix}':'{Tool}' threw exception",
                entry.Prefix, entry.OriginalName);
            throw;
        }
    }
}
