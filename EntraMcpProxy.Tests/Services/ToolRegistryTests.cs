using System.Linq;
using System.Text.Json;
using EntraMcpProxy.Services;
using FluentAssertions;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.Tests.Services;

/// <summary>
/// Tests for ToolRegistry (audit findings N7 + M15 runtime).
///
/// Important SDK constraint: Tool.InputSchema requires a valid MCP schema
/// (must have "type":"object" at minimum — bare {} is rejected). Tests use
/// the minimal valid schema {"type":"object","properties":{}}.
/// </summary>
public class ToolRegistryTests
{
    // Minimal SDK-valid schema for Tool construction.
    private static JsonElement ValidSchema() =>
        JsonDocument.Parse("""{"type":"object","properties":{}}""").RootElement.Clone();

    private static Tool T(string name, string description = "") => new()
    {
        Name = name,
        Description = description,
        InputSchema = ValidSchema(),
    };

    [Fact]
    public void RegisterTools_does_not_remove_tools_from_other_prefixes_with_substring_overlap()
    {
        var registry = new ToolRegistry();
        registry.RegisterTools("ado",   new[] { T("create"), T("list") });
        registry.RegisterTools("ado2",  new[] { T("delete") });
        registry.Count.Should().Be(3);

        // Replace 'ado' tools — the M15 bug would also wipe 'ado2' because
        // 'ado2__*' starts with 'ado__' under a string-StartsWith match. The
        // exact-prefix bucket model avoids this.
        registry.RegisterTools("ado", new[] { T("create2") });

        registry.Count.Should().Be(2);
        registry.TryResolve("ado__create2").Should().NotBeNull();
        registry.TryResolve("ado2__delete").Should().NotBeNull("ado2 must be untouched");
    }

    [Fact]
    public void GetAllTools_returns_all_registered_tools_with_prefixed_names()
    {
        var registry = new ToolRegistry();
        registry.RegisterTools("azdevops", new[] { T("ping"), T("list_projects") });
        var all = registry.GetAllTools();
        all.Select(t => t.Name).Should().BeEquivalentTo(new[] { "azdevops__ping", "azdevops__list_projects" });
    }

    [Fact]
    public void TryResolve_returns_null_for_unknown_prefix()
    {
        new ToolRegistry().TryResolve("unknown__ping").Should().BeNull();
    }

    [Fact]
    public void TryResolve_returns_null_for_malformed_name_without_double_underscore()
    {
        new ToolRegistry().TryResolve("noprefix").Should().BeNull();
    }
}
