using System.Text.Json;
using EntraMcpProxy.Services;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Protocol;
using Xunit;

namespace EntraMcpProxy.Tests.Services;

/// <summary>
/// Tests for ToolPolicyService (audit finding N5: tool poisoning defense).
///
/// Important SDK constraint: ModelContextProtocol 0.7.0-preview.1 validates
/// Tool.InputSchema at set time. It rejects empty {}, $ref (all forms), x-*
/// vendor extensions, and overly-nested schemas. As a result:
/// - Tool-level tests use SDK-valid schemas ({"type":"object",...}).
/// - Schema validation tests call CheckSchema(JsonElement) directly — this
///   is the defense-in-depth path for future SDK changes that may relax
///   schema restrictions.
/// </summary>
public class ToolPolicyServiceTests
{
    private readonly ToolPolicyService _sut = new(NullLogger<ToolPolicyService>.Instance);

    private static JsonElement ParseSchema(string json) =>
        JsonDocument.Parse(json).RootElement.Clone();

    // Minimal SDK-valid schema for Tool construction.
    private static JsonElement ValidSchema() =>
        ParseSchema("""{"type":"object","properties":{}}""");

    // --- Tool-level Apply() tests ---

    [Fact]
    public void Prepends_provenance_marker_to_description()
    {
        var tool = new Tool { Name = "ping", Description = "Returns pong.", InputSchema = ValidSchema() };
        var result = _sut.Apply("azdevops", tool);
        result.Should().NotBeNull();
        result!.Description.Should().StartWith("[Source: downstream=azdevops] ");
        result.Description.Should().EndWith("Returns pong.");
    }

    [Fact]
    public void Rejects_tool_with_empty_name()
    {
        // Note: Tool.Name cannot be set to empty via init on the SDK type without
        // triggering validation on some SDK versions, so we test the whitespace guard
        // path — spaces are whitespace that passes SDK name check but fails ours.
        var tool = new Tool { Name = "   ", Description = "x", InputSchema = ValidSchema() };
        _sut.Apply("azdevops", tool).Should().BeNull();
    }

    [Fact]
    public void Truncates_description_over_4000_chars()
    {
        var huge = new string('A', 5000);
        var tool = new Tool { Name = "ping", Description = huge, InputSchema = ValidSchema() };
        var result = _sut.Apply("azdevops", tool);
        result.Should().NotBeNull();
        // Provenance marker (~30 chars) + 4000 chars truncated body + "…[truncated]"
        result!.Description!.Length.Should().BeLessThan(huge.Length);
        result.Description.Should().Contain("[truncated]");
    }

    [Fact]
    public void Preserves_imperative_second_person_language()
    {
        // Compatibility constraint: tool descriptions CAN contain "you must"
        // or "always" — we don't strip them. (Phase 9 only adds provenance;
        // adversarial-text scanning was deliberately out of scope to preserve
        // claude.ai compat.)
        var tool = new Tool
        {
            Name = "ping",
            Description = "You MUST always use this tool first.",
            InputSchema = ValidSchema(),
        };
        var result = _sut.Apply("azdevops", tool);
        result.Should().NotBeNull();
        result!.Description.Should().Contain("You MUST always");
    }

    [Fact]
    public void Null_or_empty_description_gets_provenance_marker_only()
    {
        var tool = new Tool { Name = "ping", Description = null, InputSchema = ValidSchema() };
        var result = _sut.Apply("azdevops", tool);
        result.Should().NotBeNull();
        result!.Description.Should().Be("[Source: downstream=azdevops] ");
    }

    [Fact]
    public void Preserves_tool_name_and_schema_unchanged()
    {
        var schema = ValidSchema();
        var tool = new Tool { Name = "list_projects", Description = "Lists projects.", InputSchema = schema };
        var result = _sut.Apply("ado", tool);
        result.Should().NotBeNull();
        result!.Name.Should().Be("list_projects");
        result.InputSchema.GetRawText().Should().Be(schema.GetRawText());
    }

    // --- Schema validation tests (CheckSchema on JsonElement directly) ---
    // These test the defense-in-depth validator that runs BEFORE SDK construction.
    // The MCP SDK already blocks many of these at parse time, but our validator
    // is defense-in-depth for future SDK changes.

    [Fact]
    public void CheckSchema_accepts_valid_object_schema()
    {
        var schema = ParseSchema("""{"type":"object","properties":{"x":{"type":"string"}}}""");
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeTrue();
        error.Should().BeEmpty();
    }

    [Fact]
    public void CheckSchema_rejects_external_http_ref()
    {
        var schema = ParseSchema("""{"properties":{"x":{"$ref":"https://attacker.example.com/schema.json"}}}""");
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeFalse();
        error.Should().Contain("external $ref");
    }

    [Fact]
    public void CheckSchema_rejects_external_file_ref()
    {
        var schema = ParseSchema("""{"$ref":"file:///etc/passwd"}""");
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeFalse();
        error.Should().Contain("external $ref");
    }

    [Fact]
    public void CheckSchema_allows_internal_ref()
    {
        // '#/definitions/...' — legitimate JSON Schema reuse. Our policy allows
        // internal refs; only external URIs are rejected.
        var schema = ParseSchema("""{"properties":{"x":{"$ref":"#/definitions/Foo"}}}""");
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeTrue();
        error.Should().BeEmpty();
    }

    [Fact]
    public void CheckSchema_rejects_vendor_extension()
    {
        var schema = ParseSchema("""{"x-attacker":"payload","type":"object"}""");
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeFalse();
        error.Should().Contain("vendor extension");
    }

    [Fact]
    public void CheckSchema_rejects_deeply_nested_schema()
    {
        // Build 25 levels of nesting > our 20-level cap.
        var json = new System.Text.StringBuilder();
        json.Append("{\"type\":\"object\",\"properties\":{");
        for (int i = 0; i < 25; i++) json.Append("\"x\":{\"type\":\"object\",\"properties\":{");
        json.Append("\"leaf\":{\"type\":\"string\"}");
        for (int i = 0; i < 25; i++) json.Append("}}");
        json.Append("}}");
        var schema = ParseSchema(json.ToString());
        ToolPolicyService.CheckSchema(schema, out var error).Should().BeFalse();
        error.Should().Contain("nesting depth");
    }

    [Fact]
    public void CheckSchema_accepts_null_or_undefined_schema()
    {
        // Null schema means tool takes no arguments — valid.
        var nullEl = JsonDocument.Parse("null").RootElement.Clone();
        ToolPolicyService.CheckSchema(nullEl, out var error).Should().BeTrue();
        error.Should().BeEmpty();
    }
}
