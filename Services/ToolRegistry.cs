using System.Collections.Concurrent;
using ModelContextProtocol.Protocol;

namespace EntraMcpProxy.Services;

public class ToolRegistry
{
    private readonly ConcurrentDictionary<string, ToolEntry> _tools = new();

    public void RegisterTools(string prefix, IEnumerable<Tool> tools)
    {
        // Remove old tools for this prefix
        foreach (var key in _tools.Keys.Where(k => k.StartsWith($"{prefix}__")))
            _tools.TryRemove(key, out _);

        foreach (var tool in tools)
        {
            var prefixedName = $"{prefix}__{tool.Name}";
            _tools[prefixedName] = new ToolEntry(prefix, tool.Name, tool);
        }
    }

    public IReadOnlyList<Tool> GetAllTools()
    {
        return _tools.Values.Select(e => new Tool
        {
            Name = $"{e.Prefix}__{e.OriginalName}",
            Description = e.Tool.Description,
            InputSchema = e.Tool.InputSchema,
        }).ToList();
    }

    public ToolEntry? TryResolve(string prefixedName)
    {
        _tools.TryGetValue(prefixedName, out var entry);
        return entry;
    }

    public bool HasToolsForPrefix(string prefix) =>
        _tools.Keys.Any(k => k.StartsWith($"{prefix}__"));

    public int Count => _tools.Count;

    public record ToolEntry(string Prefix, string OriginalName, Tool Tool);
}
