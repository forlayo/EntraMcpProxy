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
using Prometheus;

namespace EntraMcpProxy.Services;

public class ProxyToolHandler
{
    private readonly ToolRegistry _toolRegistry;
    private readonly DownstreamClientManager _clientManager;
    private readonly ToolAggregatorService _aggregator;
    private readonly ToolResultWrapper _wrapper;
    private readonly DownstreamAuthorizationFilter _authz;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ProxyToolHandler> _logger;
    private readonly AuditLog _audit;

    public ProxyToolHandler(
        ToolRegistry toolRegistry,
        DownstreamClientManager clientManager,
        ToolAggregatorService aggregator,
        ToolResultWrapper wrapper,
        DownstreamAuthorizationFilter authz,
        IHttpContextAccessor httpContextAccessor,
        ILogger<ProxyToolHandler> logger,
        AuditLog audit)
    {
        _toolRegistry = toolRegistry;
        _clientManager = clientManager;
        _aggregator = aggregator;
        _wrapper = wrapper;
        _authz = authz;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _audit = audit;
    }

    public async ValueTask<ListToolsResult> HandleListToolsAsync(
        RequestContext<ListToolsRequestParams> request,
        CancellationToken cancellationToken)
    {
        var user = _httpContextAccessor.HttpContext?.User
            ?? new ClaimsPrincipal(new ClaimsIdentity());

        // First-authenticated-user-request discovery for OBO downstreams that
        // don't have a DiscoveryScope. The background loop skips these; the
        // OBO handler needs the user's bearer to exchange a downstream token.
        if (user.Identity?.IsAuthenticated == true)
        {
            foreach (var config in _clientManager.GetConfigs())
            {
                if (!config.RequiresUserContext) continue;
                if (_toolRegistry.HasToolsForPrefix(config.Prefix)) continue;

                _logger.LogInformation(
                    "Triggering lazy discovery for '{Name}' in user context",
                    config.Name);
                await _aggregator.RefreshToolsForPrefixAsync(config.Prefix, cancellationToken);
            }
        }

        var allTools = _toolRegistry.GetAllTools();
        var visible = allTools.Where(t => _authz.IsAllowed(user, t.Name)).ToList();

        _logger.LogDebug("ListTools: {Total} tools total, {Visible} visible to user", allTools.Count, visible.Count);
        return new ListToolsResult { Tools = visible };
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
            ProxyMetrics.AuthzDenials.WithLabels(toolName).Inc();
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

        // Block B: custom tracing span for tool call routing.
        using var activity = ProxyTelemetry.Source.StartActivity("ProxyToolHandler.CallTool");
        activity?.SetTag("tool", toolName);
        activity?.SetTag("downstream", entry.Prefix);
        activity?.SetTag("user_oid", user.FindFirst("oid")?.Value);

        var downstreamParams = new CallToolRequestParams
        {
            Name = entry.OriginalName,
            Arguments = request.Params?.Arguments,
        };

        try
        {
            var result = await client.CallToolAsync(downstreamParams, cancellationToken);
            sw.Stop();

            var status = result.IsError == true ? "error" : "success";
            activity?.SetTag("status", status);

            _audit.ToolInvocation(
                user,
                tool: toolName,
                args: request.Params?.Arguments,
                status: status,
                latencyMs: sw.ElapsedMilliseconds,
                correlationId: correlationId);

            // Block B: emit Prometheus metrics.
            ProxyMetrics.ToolInvocations.WithLabels(entry.Prefix, toolName, status).Inc();
            ProxyMetrics.ToolLatency.WithLabels(entry.Prefix, toolName)
                .Observe(sw.Elapsed.TotalSeconds);

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
            const string exceptionStatus = "exception";
            activity?.SetTag("status", exceptionStatus);
            activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);

            _audit.ToolInvocation(
                user,
                tool: toolName,
                args: request.Params?.Arguments,
                status: exceptionStatus,
                latencyMs: sw.ElapsedMilliseconds,
                correlationId: correlationId);

            ProxyMetrics.ToolInvocations.WithLabels(entry.Prefix, toolName, exceptionStatus).Inc();
            ProxyMetrics.ToolLatency.WithLabels(entry.Prefix, toolName)
                .Observe(sw.Elapsed.TotalSeconds);

            _logger.LogError(ex,
                "Downstream '{Prefix}':'{Tool}' threw exception",
                entry.Prefix, entry.OriginalName);
            throw;
        }
    }
}
