using System.Linq;
using System.Security.Claims;
using EntraMcpProxy.Auth;
using EntraMcpProxy.Configuration;
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

    public ProxyToolHandler(
        ToolRegistry toolRegistry,
        DownstreamClientManager clientManager,
        ToolResultWrapper wrapper,
        DownstreamAuthorizationFilter authz,
        IHttpContextAccessor httpContextAccessor,
        ILogger<ProxyToolHandler> logger)
    {
        _toolRegistry = toolRegistry;
        _clientManager = clientManager;
        _wrapper = wrapper;
        _authz = authz;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
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
            _logger.LogWarning("Authorization denied: user attempted to call '{Tool}' without permission", toolName);
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

        var downstreamParams = new CallToolRequestParams
        {
            Name = entry.OriginalName,
            Arguments = request.Params?.Arguments,
        };

        try
        {
            var result = await client.CallToolAsync(downstreamParams, cancellationToken);

            if (result.IsError == true)
            {
                // N17 (Phase 12 will fully scrub content from logs): log only the block
                // count — never the content itself (it may contain PII or attacker payloads).
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
            _logger.LogError(ex,
                "Downstream '{Prefix}':'{Tool}' threw exception",
                entry.Prefix, entry.OriginalName);
            throw;
        }
    }
}
