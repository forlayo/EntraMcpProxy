using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using ModelContextProtocol.Protocol;

namespace EntraMcpProxy.Services;

public sealed class ToolRegistry
{
    // Outer key: prefix. Inner key: original tool name (without prefix).
    // This eliminates the substring-prefix bug (M15) — prefix lookups are O(1)
    // exact, never substring.
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, ToolEntry>> _byPrefix = new();

    public void RegisterTools(string prefix, IEnumerable<Tool> tools)
    {
        // Remove the entire bucket for this prefix, then repopulate.
        var bucket = _byPrefix.GetOrAdd(prefix, _ => new ConcurrentDictionary<string, ToolEntry>());
        bucket.Clear();
        foreach (var tool in tools)
        {
            bucket[tool.Name] = new ToolEntry(prefix, tool.Name, tool);
        }
    }

    public IReadOnlyList<Tool> GetAllTools() =>
        _byPrefix.SelectMany(p => p.Value.Values).Select(e => new Tool
        {
            Name        = $"{e.Prefix}__{e.OriginalName}",
            Description = e.Tool.Description,
            InputSchema = e.Tool.InputSchema,
        }).ToList();

    public ToolEntry? TryResolve(string prefixedName)
    {
        var idx = prefixedName.IndexOf("__", StringComparison.Ordinal);
        if (idx < 0) return null;
        var prefix = prefixedName[..idx];
        var original = prefixedName[(idx + 2)..];
        if (!_byPrefix.TryGetValue(prefix, out var bucket)) return null;
        return bucket.TryGetValue(original, out var entry) ? entry : null;
    }

    public bool HasToolsForPrefix(string prefix) =>
        _byPrefix.TryGetValue(prefix, out var bucket) && !bucket.IsEmpty;

    public int Count => _byPrefix.Values.Sum(b => b.Count);

    /// <summary>
    /// Per-prefix snapshot used by ToolAggregatorService to compute change-set
    /// diffs on each refresh (finding N6).
    /// </summary>
    public IReadOnlyDictionary<string, ToolEntry> SnapshotForPrefix(string prefix) =>
        _byPrefix.TryGetValue(prefix, out var bucket)
            ? bucket.ToDictionary(kv => kv.Key, kv => kv.Value)
            : new Dictionary<string, ToolEntry>();

    public record ToolEntry(string Prefix, string OriginalName, Tool Tool);
}
